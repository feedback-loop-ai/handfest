//! `handfest revoke` subcommand and CLI revocation loading/verification helpers.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use handfest_anchors::{
    format_actor_kind, format_assurance, parse_actor_kind, sign_revocation_with, verify_chain,
    verify_revocation, SignedMandate, SignedRevocation,
};
use handfest_core::ast::{is_valid_timestamp, ActorDecl, KeyId, MandateId, MAX_RFC3339_TIMESTAMP};
use handfest_core::gate::RevocationSnapshot;
use handfest_core::revocation::{
    render_canonical_revocation, try_render_canonical_revocation, RevocationAst, RevocationTarget,
};
use handfest_core::ActorKind;
use handfest_ledger::{open_no_follow_write_no_trunc, SqliteLedger, StoredRevocation};
use serde_json::json;

use crate::parse_timestamp_arg;
use crate::sign::{resolve_signer, SignerConfig};
use crate::witness::{record_revocation_with_witness, validate_witness_mode, WitnessMode};

pub(crate) enum RevokeTargetArg {
    MandateFile(PathBuf),
    MandateId(String),
    KeyId(String),
}

pub(crate) struct RevokeArgs {
    pub(crate) target: RevokeTargetArg,
    pub(crate) effective: String,
    pub(crate) reason: Option<String>,
    pub(crate) by_kind: Option<String>,
    pub(crate) by_name: Option<String>,
    pub(crate) signer: SignerConfig,
    pub(crate) anchor_id: String,
    pub(crate) valid_from: Option<String>,
    pub(crate) valid_until: Option<String>,
    pub(crate) ledger: Option<PathBuf>,
    pub(crate) out: Option<PathBuf>,
    pub(crate) witness: WitnessMode,
}

pub(crate) fn cmd_revoke(args: &RevokeArgs) -> Result<ExitCode, String> {
    if args.witness != WitnessMode::None && args.ledger.is_none() {
        return Err("--witness requires --ledger to anchor recorded revocations".to_string());
    }
    validate_witness_mode(args.witness)?;
    if let (Some(ledger_path), Some(out_path)) = (args.ledger.as_deref(), args.out.as_deref()) {
        reject_ledger_or_sidecar_out_path(ledger_path, out_path)?;
    }

    let signer = resolve_signer(&args.signer)?;
    let signer_key = signer.key_id();

    let (target, inferred_actor) = resolve_target_and_actor(&args.target, &signer_key)?;

    let by_kind = match args.by_kind.as_deref() {
        Some(raw) => parse_actor_kind(raw).map_err(|err| format!("invalid --by-kind: {err}"))?,
        None => inferred_actor
            .as_ref()
            .map_or(ActorKind::Human, |(kind, _)| *kind),
    };
    let by_name = match args.by_name.as_deref() {
        Some(name) => name.to_string(),
        None => inferred_actor
            .map(|(_, name)| name)
            .unwrap_or_else(|| signer_key.to_string()),
    };

    let effective_at = parse_effective_arg(&args.effective)?;

    let valid_from = match args.valid_from.as_deref() {
        Some(raw) => parse_timestamp_arg("valid-from", raw)?,
        None => effective_at,
    };
    let valid_until = match args.valid_until.as_deref() {
        Some(raw) => parse_timestamp_arg("valid-until", raw)?,
        None => MAX_RFC3339_TIMESTAMP,
    };
    if valid_from >= valid_until {
        return Err(format!(
            "invalid revocation validity window [{valid_from}..{valid_until}): valid_from must be strictly less than valid_until"
        ));
    }

    let by = ActorDecl::new(by_kind, by_name, signer_key, BTreeMap::new())
        .map_err(|err| format!("invalid BY actor declaration: {err}"))?;
    let ast = RevocationAst::new(by, target, effective_at, args.reason.clone())
        .map_err(|err| format!("invalid revocation: {err}"))?;
    let canonical =
        try_render_canonical_revocation(&ast).map_err(|err| format!("render error: {err}"))?;

    let signed = sign_revocation_with(
        signer.as_ref(),
        &canonical,
        &args.anchor_id,
        valid_from,
        valid_until,
    )
    .map_err(|err| format!("failed to sign revocation: {err}"))?;

    let revocation_id = ast
        .try_revocation_id()
        .map_err(|err| format!("failed to hash revocation: {err}"))?;

    let json_text =
        serde_json::to_string_pretty(&signed).map_err(|err| format!("serialize error: {err}"))?;

    // Write --out before committing to --ledger so a failed file write never wedges retries.
    if let Some(path) = args.out.as_deref() {
        write_revocation_out_file(path, args.ledger.as_deref(), &format!("{json_text}\n"))?;
    }

    let recorded_in_ledger = if let Some(ledger_path) = args.ledger.as_deref() {
        let verified = verify_revocation(&signed)
            .map_err(|err| format!("signed revocation failed self-verification: {err}"))?;
        let ledger = SqliteLedger::open(ledger_path)
            .map_err(|err| format!("failed to open ledger '{}': {err}", ledger_path.display()))?;
        record_revocation_with_witness(
            ledger,
            ledger_path,
            args.witness,
            &verified,
            &signed.signature_hex,
        )?;
        true
    } else {
        false
    };

    if args.out.is_some() {
        let summary = json!({
            "status": "revoked",
            "revocation_id": revocation_id.to_string(),
            "recorded_in_ledger": recorded_in_ledger,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|err| err.to_string())?
        );
    } else {
        println!("{json_text}");
    }

    Ok(ExitCode::SUCCESS)
}

fn resolve_target_and_actor(
    target: &RevokeTargetArg,
    signer_key: &KeyId,
) -> Result<(RevocationTarget, Option<(ActorKind, String)>), String> {
    match target {
        RevokeTargetArg::MandateFile(path) => {
            let raw = fs::read_to_string(path)
                .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
            let signed: SignedMandate = serde_json::from_str(&raw).map_err(|err| {
                format!("invalid SignedMandate JSON in '{}': {err}", path.display())
            })?;
            let verified_list = verify_chain(&[signed]).map_err(|err| {
                format!(
                    "mandate signature verification failed for '{}': {err}",
                    path.display()
                )
            })?;
            let ast = &verified_list[0].ast;
            let mandate_id = ast
                .try_mandate_id()
                .map_err(|err| format!("failed to hash mandate '{}': {err}", path.display()))?;
            let inferred = if ast.from().key() == signer_key {
                Some((ast.from().kind(), ast.from().name().to_string()))
            } else if ast.to().key() == signer_key {
                Some((ast.to().kind(), ast.to().name().to_string()))
            } else {
                None
            };
            Ok((RevocationTarget::Mandate(mandate_id), inferred))
        }
        RevokeTargetArg::MandateId(raw) => {
            let id = MandateId::parse(raw)
                .map_err(|err| format!("invalid --target-mandate '{raw}': {err}"))?;
            Ok((RevocationTarget::Mandate(id), None))
        }
        RevokeTargetArg::KeyId(raw) => {
            let key =
                KeyId::parse(raw).map_err(|err| format!("invalid --target-key '{raw}': {err}"))?;
            Ok((RevocationTarget::Key(key), None))
        }
    }
}

fn parse_effective_arg(raw: &str) -> Result<i64, String> {
    if raw == "now" {
        return current_utc_unix_seconds();
    }
    parse_timestamp_arg("effective", raw)
}

pub(crate) fn current_utc_unix_seconds() -> Result<i64, String> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock before Unix epoch: {err}"))?;
    let ts = i64::try_from(dur.as_secs())
        .map_err(|_| "system clock timestamp exceeds i64 range".to_string())?;
    if !is_valid_timestamp(ts) {
        return Err(format!(
            "system clock timestamp {ts} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
        ));
    }
    Ok(ts)
}

pub(crate) fn load_and_verify_revocations(paths: &[PathBuf]) -> Result<RevocationSnapshot, String> {
    let mut snapshot = RevocationSnapshot::new();
    for path in paths {
        let signed = load_signed_revocation(path)?;
        let verified = verify_revocation(&signed).map_err(|err| {
            format!(
                "revocation signature verification failed for '{}': {err}",
                path.display()
            )
        })?;
        snapshot
            .insert(verified)
            .map_err(|err| format!("invalid revocation proof in '{}': {err}", path.display()))?;
    }
    Ok(snapshot)
}

fn load_signed_revocation(path: &Path) -> Result<SignedRevocation, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| {
        format!(
            "invalid SignedRevocation JSON in '{}': {err}",
            path.display()
        )
    })
}

pub(crate) fn verify_stored_revocations_signatures(
    stored: &[StoredRevocation],
) -> Result<(), String> {
    for record in stored {
        let signed = SignedRevocation {
            canonical_words: render_canonical_revocation(&record.verified.ast),
            anchor_id: record.verified.proof.anchor_id.clone(),
            assurance: format_assurance(record.verified.proof.assurance).to_string(),
            actor_kind: format_actor_kind(record.verified.proof.actor_kind).to_string(),
            signer_key: record.verified.proof.signer_key.to_string(),
            valid_from: record.verified.proof.valid_from,
            valid_until: record.verified.proof.valid_until,
            signature_hex: record.signature_hex.clone(),
        };
        verify_revocation(&signed).map_err(|err| {
            format!(
                "stored revocation {} failed cryptographic verification: {err}",
                record.revocation_id
            )
        })?;
    }
    Ok(())
}

#[derive(Debug, clap::Args)]
pub(crate) struct RevokeCliArgs {
    /// Path to a SignedMandate JSON file whose canonical MandateId will be revoked.
    #[arg(
        long,
        required_unless_present_any = ["target_mandate", "target_key"],
        conflicts_with_all = ["target_mandate", "target_key"]
    )]
    pub(crate) mandate: Option<PathBuf>,
    /// Target mandate digest to revoke (`sha256:<64-lowercase-hex>`).
    #[arg(
        long,
        required_unless_present_any = ["mandate", "target_key"],
        conflicts_with_all = ["mandate", "target_key"]
    )]
    pub(crate) target_mandate: Option<String>,
    /// Target actor KeyId to revoke (`<scheme>:<value>`).
    #[arg(
        long,
        required_unless_present_any = ["mandate", "target_mandate"],
        conflicts_with_all = ["mandate", "target_mandate"]
    )]
    pub(crate) target_key: Option<String>,
    /// Effective UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`, Unix seconds, or `now`).
    #[arg(long)]
    pub(crate) effective: String,
    /// Optional human-readable revocation reason.
    #[arg(long)]
    pub(crate) reason: Option<String>,
    /// Optional revoking actor kind (`human`, `org`, `agent`, `service`).
    #[arg(long)]
    pub(crate) by_kind: Option<String>,
    /// Optional revoking actor display name.
    #[arg(long)]
    pub(crate) by_name: Option<String>,
    /// Path to the Ed25519 secret key JSON file created by `handfest keygen`.
    #[arg(
        long,
        required_unless_present_any = ["ssh_key", "fido2_cred", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["ssh_key", "fido2_cred", "fido2_device", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    pub(crate) key: Option<PathBuf>,
    /// Path to an OpenSSH FIDO2 key handle or `.pub` file (`sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`).
    #[arg(
        long,
        required_unless_present_any = ["key", "fido2_cred", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["key", "fido2_cred", "fido2_device", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    pub(crate) ssh_key: Option<PathBuf>,
    /// Path to a FIDO2 Ed25519 credential metadata JSON file.
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["key", "ssh_key", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    pub(crate) fido2_cred: Option<PathBuf>,
    /// Optional FIDO2 HID device path (used with --fido2-cred).
    #[arg(
        long,
        requires = "fido2_cred",
        conflicts_with_all = ["key", "ssh_key", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    pub(crate) fido2_device: Option<String>,
    /// OpenPGP / GPG smartcard Ed25519 key fingerprint (40-hex or 64-hex).
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "fido2_cred", "piv_pubkey"],
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "piv_pubkey", "piv_module", "piv_id"]
    )]
    pub(crate) gpg_key: Option<String>,
    /// Path to a PEM-encoded RFC 8410 Ed25519 SubjectPublicKeyInfo file for a PIV slot.
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "fido2_cred", "gpg_key"],
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "gpg_key"]
    )]
    pub(crate) piv_pubkey: Option<PathBuf>,
    /// Path to the PKCS#11 shared library (used with --piv-pubkey).
    #[arg(
        long,
        requires = "piv_pubkey",
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "gpg_key"]
    )]
    pub(crate) piv_module: Option<String>,
    /// PKCS#11 hex key ID for the PIV slot (default: "02" for slot 9c).
    #[arg(
        long,
        requires = "piv_pubkey",
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "gpg_key"]
    )]
    pub(crate) piv_id: Option<String>,
    /// Optional anchor validity start timestamp (defaults to --effective).
    #[arg(long)]
    pub(crate) valid_from: Option<String>,
    /// Optional anchor validity end timestamp (defaults to 9999-12-31T23:59:59Z).
    #[arg(long)]
    pub(crate) valid_until: Option<String>,
    /// Trust anchor identifier recorded in the SignedRevocation envelope.
    #[arg(long)]
    pub(crate) anchor_id: Option<String>,
    /// Optional SQLite ledger database path to immediately record the revocation.
    #[arg(long)]
    pub(crate) ledger: Option<PathBuf>,
    /// Optional path to write the SignedRevocation JSON (prints JSON to stdout if omitted).
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    /// Optional external checkpoint witness backend (`none` default, or `ots` with feature `witness-ots`).
    #[arg(long, value_enum, default_value_t = WitnessMode::None)]
    pub(crate) witness: WitnessMode,
}

pub(crate) fn run_revoke_cli(cli: RevokeCliArgs) -> Result<ExitCode, String> {
    let target = match (cli.mandate, cli.target_mandate, cli.target_key) {
        (Some(path), None, None) => RevokeTargetArg::MandateFile(path),
        (None, Some(id), None) => RevokeTargetArg::MandateId(id),
        (None, None, Some(key_id)) => RevokeTargetArg::KeyId(key_id),
        _ => {
            return Err(
                "exactly one of --mandate, --target-mandate, or --target-key must be supplied"
                    .to_string(),
            );
        }
    };
    let signer = crate::build_signer_config(
        cli.key,
        cli.ssh_key,
        cli.fido2_cred,
        cli.fido2_device,
        cli.gpg_key,
        cli.piv_pubkey,
        cli.piv_module,
        cli.piv_id,
    )?;
    let anchor_id = cli
        .anchor_id
        .unwrap_or_else(|| signer.default_anchor_id().to_string());
    cmd_revoke(&RevokeArgs {
        target,
        effective: cli.effective,
        reason: cli.reason,
        by_kind: cli.by_kind,
        by_name: cli.by_name,
        signer,
        anchor_id,
        valid_from: cli.valid_from,
        valid_until: cli.valid_until,
        ledger: cli.ledger,
        out: cli.out,
        witness: cli.witness,
    })
}

const FORBIDDEN_LEDGER_OUT_SUFFIXES: &[&str] =
    &["", ".checkpoints.jsonl", "-wal", "-shm", "-journal"];
const MAX_SYMLINK_HOPS: usize = 40;

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn resolve_path_without_leaf(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?;
    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    Some(fs::canonicalize(parent).ok()?.join(file_name))
}

fn resolve_path_following_symlinks(path: &Path) -> Result<PathBuf, String> {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        if let Some(normalized) = resolve_path_without_leaf(&current) {
            current = normalized;
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = fs::read_link(&current).map_err(|err| {
                    format!("failed to read symlink '{}': {err}", current.display())
                })?;
                current = if target.is_absolute() {
                    target
                } else {
                    let parent = match current.parent() {
                        Some(dir) if !dir.as_os_str().is_empty() => dir,
                        _ => Path::new("."),
                    };
                    parent.join(target)
                };
            }
            Ok(_) => {
                return Ok(fs::canonicalize(&current).unwrap_or(current));
            }
            Err(_) => {
                return Ok(current);
            }
        }
    }
    Err(format!(
        "path '{}' exceeds maximum symlink depth ({MAX_SYMLINK_HOPS}) or contains a symlink cycle",
        path.display()
    ))
}

fn collect_path_forms(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut forms = vec![path.to_path_buf()];
    let resolved = resolve_path_following_symlinks(path)?;
    if !forms.contains(&resolved) {
        forms.push(resolved);
    }
    if let Some(no_leaf) = resolve_path_without_leaf(path) {
        if !forms.contains(&no_leaf) {
            forms.push(no_leaf);
        }
    }
    Ok(forms)
}

#[cfg(unix)]
fn file_inode_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(unix)]
fn open_file_inode_identity(file: &fs::File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().ok().map(|m| (m.dev(), m.ino()))
}

fn collect_forbidden_ledger_paths(ledger_path: &Path) -> Result<Vec<PathBuf>, String> {
    let ledger_bases = collect_path_forms(ledger_path)?;
    let mut forbidden_all = Vec::new();
    for base in &ledger_bases {
        for suffix in FORBIDDEN_LEDGER_OUT_SUFFIXES {
            let candidate = append_path_suffix(base, suffix);
            if !forbidden_all.contains(&candidate) {
                forbidden_all.push(candidate.clone());
            }
            if let Ok(resolved) = resolve_path_following_symlinks(&candidate) {
                if !forbidden_all.contains(&resolved) {
                    forbidden_all.push(resolved);
                }
            }
        }
    }
    Ok(forbidden_all)
}

fn reject_ledger_or_sidecar_out_path(ledger_path: &Path, out_path: &Path) -> Result<(), String> {
    let out_forms = collect_path_forms(out_path)?;
    let forbidden_paths = collect_forbidden_ledger_paths(ledger_path)?;
    #[cfg(unix)]
    let out_inode = file_inode_identity(out_path);

    for forbidden in &forbidden_paths {
        if out_forms.contains(forbidden) {
            return Err(format!(
                "--out '{}' must not point to --ledger '{}' or its sidecar files",
                out_path.display(),
                ledger_path.display()
            ));
        }
        #[cfg(unix)]
        if let (Some(out_id), Some(forbidden_id)) = (out_inode, file_inode_identity(forbidden)) {
            if out_id == forbidden_id {
                return Err(format!(
                    "--out '{}' must not point to --ledger '{}' or its sidecar files (hardlink alias)",
                    out_path.display(),
                    ledger_path.display()
                ));
            }
        }
    }
    Ok(())
}

fn write_revocation_out_file(
    out_path: &Path,
    ledger_path: Option<&Path>,
    content: &str,
) -> Result<(), String> {
    let mut file = open_no_follow_write_no_trunc(out_path).map_err(|err| {
        if fs::symlink_metadata(out_path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            format!(
                "refusing to write --out '{}' through symlink: {err}",
                out_path.display()
            )
        } else {
            format!("failed to open '{}' for writing: {err}", out_path.display())
        }
    })?;

    let meta = file
        .metadata()
        .map_err(|err| format!("failed to fstat '{}': {err}", out_path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "--out '{}' must be a regular file",
            out_path.display()
        ));
    }

    #[cfg(unix)]
    if let Some(lp) = ledger_path {
        if let Some(open_id) = open_file_inode_identity(&file) {
            for forbidden in collect_forbidden_ledger_paths(lp)? {
                if file_inode_identity(&forbidden) == Some(open_id) {
                    return Err(format!(
                        "--out '{}' must not point to --ledger '{}' or its sidecar files (hardlink alias)",
                        out_path.display(),
                        lp.display()
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = ledger_path;

    file.set_len(0)
        .map_err(|err| format!("failed to truncate '{}': {err}", out_path.display()))?;
    file.write_all(content.as_bytes())
        .map_err(|err| format!("failed to write '{}': {err}", out_path.display()))?;
    file.flush()
        .map_err(|err| format!("failed to flush '{}': {err}", out_path.display()))?;
    Ok(())
}
