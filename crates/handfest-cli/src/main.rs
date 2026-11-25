//! Reference CLI for formatting, signing, verifying, checking, and auditing `handfest` mandates.

mod facts;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use handfest_anchors::{verify_chain, Ed25519KeyFile, Ed25519Keypair, SignedMandate};
use handfest_core::ast::{is_valid_timestamp, parse_rfc3339_utc, KeyId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::ActionRequest;
use handfest_core::lattice::subsumes;
use handfest_core::Verdict;
use handfest_ledger::SqliteLedger;
use serde_json::json;

use crate::facts::parse_facts_arg;

#[derive(Debug, Parser)]
#[command(
    name = "handfest",
    version,
    about = "Executable Ricardian mandates CLI (HANDFEST v1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Parses a HANDFEST v1 file and prints canonical text.
    Fmt {
        /// Path to a HANDFEST v1 mandate file.
        file: PathBuf,
    },
    /// Generates an Ed25519 keypair and prints its ed25519:<hex> public KeyId.
    Keygen {
        /// Optional path to write the secret key JSON file (prints JSON to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Canonicalizes and signs a HANDFEST v1 mandate into a SignedMandate JSON envelope.
    Sign {
        /// Path to the HANDFEST v1 mandate text file.
        #[arg(long)]
        mandate: PathBuf,
        /// Path to the Ed25519 secret key JSON file created by `handfest keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Anchor validity start timestamp (RFC 3339 UTC or Unix seconds).
        #[arg(long)]
        valid_from: String,
        /// Anchor validity end timestamp (RFC 3339 UTC or Unix seconds).
        #[arg(long)]
        valid_until: String,
        /// Trust anchor identifier recorded in the SignedMandate envelope.
        #[arg(long, default_value = "local-ed25519")]
        anchor_id: String,
        /// Optional path to write the SignedMandate JSON (prints JSON to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verifies 1+ signed mandates as a delegation chain (signatures + lattice narrowing).
    Verify {
        /// Ordered signed mandate JSON files (root first, leaf last).
        #[arg(required = true)]
        signed: Vec<PathBuf>,
    },
    /// Evaluates a request against a mandate chain, records receipt & quotas in SQLite,
    /// and exits 0 on Permit or non-zero on Deny.
    Check {
        /// Path to the SQLite ledger database file.
        #[arg(long)]
        ledger: PathBuf,
        /// Ordered signed mandate JSON files (root first, leaf last).
        #[arg(long, required = true, num_args = 1..)]
        chain: Vec<PathBuf>,
        /// Concrete requesting actor KeyId (e.g. ed25519:<hex>).
        #[arg(long)]
        actor_key: String,
        /// Concrete action identifier (e.g. git.pr.merge).
        #[arg(long)]
        action: String,
        /// Concrete resource kind (e.g. repo).
        #[arg(long)]
        resource_kind: String,
        /// Concrete resource identifier (e.g. feedback-loop-ai/handfest).
        #[arg(long)]
        resource_id: String,
        /// Gate-verified facts as a JSON object string (or @file / path to JSON file).
        #[arg(long, default_value = "{}")]
        facts: String,
        /// Explicit evaluation UTC timestamp in RFC 3339 format (YYYY-MM-DDTHH:MM:SSZ).
        #[arg(long)]
        now: String,
    },
    /// Verifies ledger hash-chain integrity and optionally prints an actor's TrackRecord.
    Audit {
        /// Path to the SQLite ledger database file.
        #[arg(long)]
        ledger: PathBuf,
        /// Optional actor KeyId to compute a TrackRecord projection for.
        #[arg(long)]
        actor_key: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Commands::Fmt { file } => cmd_fmt(&file),
        Commands::Keygen { out } => cmd_keygen(out.as_deref()),
        Commands::Sign {
            mandate,
            key,
            valid_from,
            valid_until,
            anchor_id,
            out,
        } => cmd_sign(
            &mandate,
            &key,
            &valid_from,
            &valid_until,
            &anchor_id,
            out.as_deref(),
        ),
        Commands::Verify { signed } => cmd_verify(&signed),
        Commands::Check {
            ledger,
            chain,
            actor_key,
            action,
            resource_kind,
            resource_id,
            facts,
            now,
        } => cmd_check(&CheckArgs {
            ledger,
            chain,
            actor_key,
            action,
            resource_kind,
            resource_id,
            facts,
            now,
        }),
        Commands::Audit { ledger, actor_key } => cmd_audit(&ledger, actor_key.as_deref()),
    }
}

struct CheckArgs {
    ledger: PathBuf,
    chain: Vec<PathBuf>,
    actor_key: String,
    action: String,
    resource_kind: String,
    resource_id: String,
    facts: String,
    now: String,
}

fn cmd_fmt(file: &Path) -> Result<ExitCode, String> {
    let raw = fs::read_to_string(file)
        .map_err(|err| format!("failed to read '{}': {err}", file.display()))?;
    let ast = parse_mandate(&raw).map_err(|err| format!("parse error: {err}"))?;
    let canonical = try_render_canonical(&ast).map_err(|err| format!("render error: {err}"))?;
    print!("{canonical}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_keygen(out: Option<&Path>) -> Result<ExitCode, String> {
    let keypair = Ed25519Keypair::generate();
    let key_file = keypair.to_key_file();
    let json_text =
        serde_json::to_string_pretty(&key_file).map_err(|err| format!("serialize error: {err}"))?;

    if let Some(path) = out {
        write_secret_file(path, &format!("{json_text}\n"))?;
        println!("{}", key_file.key_id);
    } else {
        println!("{json_text}");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_sign(
    mandate_path: &Path,
    key_path: &Path,
    valid_from_raw: &str,
    valid_until_raw: &str,
    anchor_id: &str,
    out: Option<&Path>,
) -> Result<ExitCode, String> {
    let mandate_raw = fs::read_to_string(mandate_path)
        .map_err(|err| format!("failed to read '{}': {err}", mandate_path.display()))?;
    let ast = parse_mandate(&mandate_raw).map_err(|err| format!("invalid mandate: {err}"))?;
    let canonical = try_render_canonical(&ast).map_err(|err| format!("render error: {err}"))?;

    let key_raw = fs::read_to_string(key_path)
        .map_err(|err| format!("failed to read '{}': {err}", key_path.display()))?;
    let key_file: Ed25519KeyFile =
        serde_json::from_str(&key_raw).map_err(|err| format!("invalid key file JSON: {err}"))?;
    let keypair = Ed25519Keypair::from_key_file(&key_file)
        .map_err(|err| format!("failed to load Ed25519 key: {err}"))?;

    let valid_from = parse_timestamp_arg("valid-from", valid_from_raw)?;
    let valid_until = parse_timestamp_arg("valid-until", valid_until_raw)?;

    let signed = keypair
        .sign_mandate(&canonical, anchor_id, valid_from, valid_until)
        .map_err(|err| format!("failed to sign mandate: {err}"))?;
    let mandate_id = ast
        .try_mandate_id()
        .map_err(|err| format!("failed to hash mandate: {err}"))?;
    let json_text =
        serde_json::to_string_pretty(&signed).map_err(|err| format!("serialize error: {err}"))?;

    if let Some(path) = out {
        fs::write(path, format!("{json_text}\n"))
            .map_err(|err| format!("failed to write '{}': {err}", path.display()))?;
        println!("{mandate_id}");
    } else {
        println!("{json_text}");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(paths: &[PathBuf]) -> Result<ExitCode, String> {
    let signed = load_signed_mandates(paths)?;
    let verified =
        verify_chain(&signed).map_err(|err| format!("signature verification failed: {err}"))?;

    if verified[0].ast.parent().is_some() {
        return Err("root mandate must not declare a PARENT digest".to_string());
    }
    for (hop, pair) in verified.windows(2).enumerate() {
        subsumes(&pair[0].ast, &pair[1].ast).map_err(|err| {
            format!(
                "attenuation check failed at hop {hop} -> {}: {err}",
                hop + 1
            )
        })?;
    }

    let mut chain_ids = Vec::with_capacity(verified.len());
    for vm in &verified {
        let mid = vm
            .ast
            .try_mandate_id()
            .map_err(|err| format!("failed to hash mandate: {err}"))?;
        chain_ids.push(mid.to_string());
    }

    let output = json!({
        "status": "verified",
        "hops": verified.len(),
        "chain_ids": chain_ids,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(args: &CheckArgs) -> Result<ExitCode, String> {
    let signed = load_signed_mandates(&args.chain)?;
    let verified =
        verify_chain(&signed).map_err(|err| format!("signature verification failed: {err}"))?;

    let actor_key = KeyId::parse(&args.actor_key)
        .map_err(|err| format!("invalid --actor-key '{}': {err}", args.actor_key))?;
    let now = parse_rfc3339_utc(&args.now)
        .map_err(|err| format!("invalid --now '{}': {err}", args.now))?;
    let facts = parse_facts_arg(&args.facts)?;

    let request = ActionRequest {
        actor_key,
        action: args.action.clone(),
        resource_kind: args.resource_kind.clone(),
        resource_id: args.resource_id.clone(),
    };

    let mut ledger = SqliteLedger::open(&args.ledger)
        .map_err(|err| format!("failed to open ledger '{}': {err}", args.ledger.display()))?;
    let (verdict, receipt) = ledger
        .evaluate_and_record(&verified, &request, &facts, now)
        .map_err(|err| format!("ledger evaluation failed: {err}"))?;

    match verdict {
        Verdict::Permit => {
            let output = json!({
                "verdict": "permit",
                "receipt_hash": receipt.receipt_hash.to_string(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }
        Verdict::Deny { reason } => {
            let output = json!({
                "verdict": "deny",
                "reason": reason,
                "receipt_hash": receipt.receipt_hash.to_string(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_audit(ledger_path: &Path, actor_key_raw: Option<&str>) -> Result<ExitCode, String> {
    let actor_key = match actor_key_raw {
        Some(raw) => {
            Some(KeyId::parse(raw).map_err(|err| format!("invalid --actor-key '{raw}': {err}"))?)
        }
        None => None,
    };

    let ledger = SqliteLedger::open_read_only(ledger_path)
        .map_err(|err| format!("failed to open ledger '{}': {err}", ledger_path.display()))?;
    let (verified_receipts, track_record) = ledger
        .audit_snapshot(actor_key.as_ref())
        .map_err(|err| format!("audit integrity check failed: {err}"))?;

    let output = match track_record {
        Some(record) => json!({
            "status": "ok",
            "verified_receipts": verified_receipts,
            "track_record": record,
        }),
        None => json!({
            "status": "ok",
            "verified_receipts": verified_receipts,
        }),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}

fn load_signed_mandates(paths: &[PathBuf]) -> Result<Vec<SignedMandate>, String> {
    let mut mandates = Vec::with_capacity(paths.len());
    for path in paths {
        let raw = fs::read_to_string(path)
            .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
        let signed: SignedMandate = serde_json::from_str(&raw)
            .map_err(|err| format!("invalid SignedMandate JSON in '{}': {err}", path.display()))?;
        mandates.push(signed);
    }
    Ok(mandates)
}

fn parse_timestamp_arg(flag: &str, raw: &str) -> Result<i64, String> {
    if let Ok(ts) = parse_rfc3339_utc(raw) {
        return Ok(ts);
    }
    if let Ok(ts) = raw.parse::<i64>() {
        if is_valid_timestamp(ts) {
            return Ok(ts);
        }
        return Err(format!(
            "--{flag} timestamp {ts} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
        ));
    }
    Err(format!(
        "invalid --{flag} '{raw}': expected RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ) or Unix seconds"
    ))
}

#[cfg(unix)]
fn write_secret_file(path: &Path, content: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let pid = std::process::id();

    let (tmp_path, mut file) = create_unique_secret_temp(parent, pid)?;
    let write_res = (|| -> std::io::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to write '{}': {err}", path.display()));
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to install '{}': {err}", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
fn create_unique_secret_temp(parent: &Path, pid: u32) -> Result<(PathBuf, fs::File), String> {
    use std::os::unix::fs::OpenOptionsExt;

    for attempt in 0u32..64 {
        let tmp_path = parent.join(format!(".handfest-secret-{pid}-{attempt}.tmp"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "failed to create temporary secret file in '{}': {err}",
                    parent.display()
                ));
            }
        }
    }
    Err(format!(
        "failed to allocate unique temporary secret file in '{}'",
        parent.display()
    ))
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, content: &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|err| format!("failed to create '{}': {err}", path.display()))?;
    file.write_all(content.as_bytes())
        .map_err(|err| format!("failed to write '{}': {err}", path.display()))
}
