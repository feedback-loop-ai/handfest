//! `handfest init` out-of-band bootstrap subcommand.
//!
//! Creates or verifies an outside-workspace Handfest configuration directory (`~/.handfest` by
//! default), initializes the SQLite ledger without resetting existing state/quotas, generates or
//! reuses the agent Ed25519 keypair, and writes a **public-only** `profile.json` so AI agents can
//! read public `KeyId`s without ever touching private keys.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use handfest_anchors::{CommandRunner, Ed25519KeyFile, Ed25519Keypair, SystemCommandRunner};
use handfest_core::ast::{ActorDecl, KeyId};
use handfest_core::ActorKind;
use handfest_ledger::SqliteLedger;
use serde::{Deserialize, Serialize};

use crate::keyid::{
    path_to_utf8_string, resolve_principal_key_with_runner, PrincipalKeyArgs, PrincipalKeySource,
    SignerKind,
};
use crate::revoke::verify_stored_revocations_signatures;

pub(crate) const PROFILE_SCHEMA_V1: &str = "handfest.profile/v1";

/// Public-only profile written to `<dir>/profile.json` (`0644` on Unix).
///
/// Strictly forbids unknown fields and never stores private key material or PINs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HandfestProfile {
    pub(crate) schema: String,
    pub(crate) principal_name: String,
    pub(crate) principal_key_id: String,
    pub(crate) signer_kind: SignerKind,
    pub(crate) signer_hint: String,
    pub(crate) agent_name: String,
    pub(crate) agent_key_id: String,
    pub(crate) mandates_dir: String,
    pub(crate) ledger_path: String,
    pub(crate) policy_map_path: String,
}

/// CLI arguments for `handfest init`.
#[derive(Debug, Clone, Args)]
pub(crate) struct InitCliArgs {
    /// Target outside-workspace config directory (defaults to `$HANDFEST_HOME` or `~/.handfest`).
    #[arg(long)]
    pub(crate) dir: Option<PathBuf>,
    /// Human principal display name for drafted HANDFEST v1 mandates.
    #[arg(long)]
    pub(crate) principal_name: String,
    /// Agent actor display name for drafted HANDFEST v1 mandates.
    #[arg(long, default_value = "agent")]
    pub(crate) agent_name: String,
    /// Optional path to an existing agent Ed25519 key JSON file to reuse instead of `<dir>/agent.key.json`.
    #[arg(long)]
    pub(crate) agent_key: Option<PathBuf>,
    /// Allow initializing inside a git working tree (unsafe for production agent workspaces).
    #[arg(long, default_value_t = false)]
    pub(crate) allow_in_repo: bool,
    /// Principal public key source (mutually exclusive).
    #[command(flatten)]
    pub(crate) principal_key: PrincipalKeyArgs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct InitSummary {
    pub(crate) status: &'static str,
    pub(crate) dir: String,
    pub(crate) profile_path: String,
    pub(crate) mandates_dir: String,
    pub(crate) ledger_path: String,
    pub(crate) policy_map_path: String,
    pub(crate) hooks_dir: String,
    pub(crate) templates_dir: String,
    pub(crate) agent_key_path: String,
    pub(crate) agent_key_created: bool,
    pub(crate) ledger_created: bool,
    pub(crate) principal_name: String,
    pub(crate) principal_key_id: String,
    pub(crate) signer_kind: SignerKind,
    pub(crate) signer_hint: String,
    pub(crate) agent_name: String,
    pub(crate) agent_key_id: String,
    pub(crate) next_step_sign_command: String,
}

struct ConfigDirs {
    root: PathBuf,
    mandates_dir: PathBuf,
    hooks_dir: PathBuf,
    templates_dir: PathBuf,
    ledger_path: PathBuf,
    policy_map_path: PathBuf,
    profile_path: PathBuf,
}

pub(crate) fn run_init_cli(args: InitCliArgs) -> Result<ExitCode, String> {
    let dir = resolve_init_dir(args.dir)?;
    let principal_source = args.principal_key.into_source()?;
    let summary = init_profile_with_runner(
        &dir,
        &args.principal_name,
        &args.agent_name,
        args.agent_key.as_deref(),
        args.allow_in_repo,
        &principal_source,
        SystemCommandRunner,
    )?;
    let rendered =
        serde_json::to_string_pretty(&summary).map_err(|err| format!("serialize error: {err}"))?;
    println!("{rendered}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn init_profile_with_runner<R: CommandRunner>(
    dir: &Path,
    principal_name: &str,
    agent_name: &str,
    explicit_agent_key: Option<&Path>,
    allow_in_repo: bool,
    principal_source: &PrincipalKeySource,
    runner: R,
) -> Result<InitSummary, String> {
    let abs_dir = absolutize_lexical_path(dir)?;
    let _ = path_to_utf8_string(&abs_dir, "--dir")?;
    if !allow_in_repo {
        reject_git_worktree(&abs_dir)?;
    }

    let principal = resolve_principal_key_with_runner(principal_source, runner)?;
    validate_actor_name(
        "--principal-name",
        principal_name,
        ActorKind::Human,
        &principal.key_id,
    )?;
    validate_actor_name(
        "--agent-name",
        agent_name,
        ActorKind::Agent,
        &principal.key_id,
    )?;

    let planned_profile = abs_dir.join("profile.json");
    if let Some(explicit) = explicit_agent_key {
        let abs_agent = absolutize_lexical_path(explicit)?;
        if paths_collide(&abs_agent, &planned_profile) {
            return Err(format!(
                "--agent-key '{}' must not point to '{}'",
                explicit.display(),
                planned_profile.display()
            ));
        }
        let _ = load_ed25519_key_id(explicit)?;
    }
    if let PrincipalKeySource::LocalEd25519(pk_path) = principal_source {
        let abs_pk = absolutize_lexical_path(pk_path)?;
        if paths_collide(&abs_pk, &planned_profile) {
            return Err(format!(
                "--key '{}' must not point to '{}'",
                pk_path.display(),
                planned_profile.display()
            ));
        }
    }

    let dirs = prepare_config_dirs(&abs_dir, allow_in_repo)?;
    let (agent_key_path, agent_key_id, agent_key_created) =
        load_or_create_agent_key(&dirs.root, explicit_agent_key)?;
    if agent_key_id == principal.key_id {
        return Err(
            "principal and agent must not share the same signing key (self-delegation refused)"
                .to_string(),
        );
    }
    let ledger_created = init_or_verify_ledger(&dirs.ledger_path)?;

    let root_str = path_to_utf8_string(&dirs.root, "--dir")?;
    let mandates_dir_str = path_to_utf8_string(&dirs.mandates_dir, "mandates_dir")?;
    let ledger_path_str = path_to_utf8_string(&dirs.ledger_path, "ledger_path")?;
    let policy_map_path_str = path_to_utf8_string(&dirs.policy_map_path, "policy_map_path")?;
    let hooks_dir_str = path_to_utf8_string(&dirs.hooks_dir, "hooks_dir")?;
    let templates_dir_str = path_to_utf8_string(&dirs.templates_dir, "templates_dir")?;
    let profile_path_str = path_to_utf8_string(&dirs.profile_path, "profile_path")?;
    let agent_key_path_str = path_to_utf8_string(&agent_key_path, "agent_key_path")?;
    let signer_hint = normalize_signer_hint(principal.signer_kind, &principal.signer_hint)?;

    let profile = HandfestProfile {
        schema: PROFILE_SCHEMA_V1.to_string(),
        principal_name: principal_name.to_string(),
        principal_key_id: principal.key_id.to_string(),
        signer_kind: principal.signer_kind,
        signer_hint: signer_hint.clone(),
        agent_name: agent_name.to_string(),
        agent_key_id: agent_key_id.to_string(),
        mandates_dir: mandates_dir_str.clone(),
        ledger_path: ledger_path_str.clone(),
        policy_map_path: policy_map_path_str.clone(),
    };
    let profile_json =
        serde_json::to_string_pretty(&profile).map_err(|err| format!("serialize error: {err}"))?;
    write_public_file(&dirs.profile_path, &format!("{profile_json}\n"))?;

    let next_step_sign_command =
        format_next_step_sign_command(&mandates_dir_str, principal.signer_kind, &signer_hint);

    Ok(InitSummary {
        status: "initialized",
        dir: root_str,
        profile_path: profile_path_str,
        mandates_dir: mandates_dir_str,
        ledger_path: ledger_path_str,
        policy_map_path: policy_map_path_str,
        hooks_dir: hooks_dir_str,
        templates_dir: templates_dir_str,
        agent_key_path: agent_key_path_str,
        agent_key_created,
        ledger_created,
        principal_name: profile.principal_name,
        principal_key_id: profile.principal_key_id,
        signer_kind: profile.signer_kind,
        signer_hint: profile.signer_hint,
        agent_name: profile.agent_name,
        agent_key_id: profile.agent_key_id,
        next_step_sign_command,
    })
}

fn validate_actor_name(
    flag: &str,
    name: &str,
    kind: ActorKind,
    key_id: &KeyId,
) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err(format!("invalid {flag} '{name}': name must not be empty"));
    }
    ActorDecl::new(kind, name.to_string(), key_id.clone(), BTreeMap::new())
        .map(|_| ())
        .map_err(|err| format!("invalid {flag} '{name}': {err}"))
}

fn resolve_init_dir(dir: Option<PathBuf>) -> Result<PathBuf, String> {
    resolve_init_dir_from(
        dir,
        std::env::var_os("HANDFEST_HOME"),
        std::env::var_os("HOME"),
    )
}

fn resolve_init_dir_from(
    dir: Option<PathBuf>,
    handfest_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, String> {
    if let Some(explicit) = dir {
        if explicit.as_os_str().is_empty() {
            return Err("--dir must not be empty".to_string());
        }
        return Ok(explicit);
    }
    if let Some(env_dir) = handfest_home.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(env_dir));
    }
    if let Some(home_dir) = home.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(home_dir).join(".handfest"));
    }
    Err(
        "cannot determine default handfest directory: pass --dir or set HANDFEST_HOME / HOME"
            .to_string(),
    )
}

fn absolutize_lexical_path(path: &Path) -> Result<PathBuf, String> {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .join(path)
    };
    let mut out = PathBuf::new();
    for comp in raw.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

fn paths_collide(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

fn normalize_signer_hint(kind: SignerKind, hint: &str) -> Result<String, String> {
    if matches!(kind, SignerKind::OpenPgp) {
        return Ok(hint.to_string());
    }
    let abs = absolutize_lexical_path(Path::new(hint))?;
    path_to_utf8_string(&abs, "signer_hint")
}

fn reject_git_worktree(dir: &Path) -> Result<(), String> {
    let abs = absolutize_lexical_path(dir)?;
    check_ancestors_for_git(&abs, dir)?;

    if let Some(existing) = abs
        .ancestors()
        .find(|anc| fs::symlink_metadata(anc).is_ok())
    {
        let canon = fs::canonicalize(existing).map_err(|err| {
            format!(
                "failed to canonicalize '{}' for git worktree check: {err}",
                existing.display()
            )
        })?;
        check_ancestors_for_git(&canon, dir)?;
    }
    Ok(())
}

fn check_ancestors_for_git(probe: &Path, display_dir: &Path) -> Result<(), String> {
    for ancestor in probe.ancestors() {
        if fs::symlink_metadata(ancestor.join(".git")).is_ok() {
            return Err(format!(
                "refusing to initialize '{}' inside git working tree '{}'; use an outside-workspace path (e.g. ~/.handfest) or pass --allow-in-repo to override",
                display_dir.display(),
                ancestor.display()
            ));
        }
    }
    Ok(())
}

fn prepare_config_dirs(dir: &Path, allow_in_repo: bool) -> Result<ConfigDirs, String> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if !meta.is_dir() {
            return Err(format!(
                "target '{}' exists and is not a directory",
                dir.display()
            ));
        }
    }
    fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create directory '{}': {err}", dir.display()))?;
    set_dir_mode_0700(dir)?;

    let mandates_dir = dir.join("mandates");
    let state_dir = dir.join("state");
    let hooks_dir = dir.join("hooks");
    let templates_dir = dir.join("templates");
    for sub in [&mandates_dir, &state_dir, &hooks_dir, &templates_dir] {
        fs::create_dir_all(sub)
            .map_err(|err| format!("failed to create directory '{}': {err}", sub.display()))?;
        if !allow_in_repo {
            let canon = fs::canonicalize(sub).map_err(|err| {
                format!(
                    "failed to canonicalize '{}' for git worktree check: {err}",
                    sub.display()
                )
            })?;
            check_ancestors_for_git(&canon, sub)?;
        }
    }

    Ok(ConfigDirs {
        root: dir.to_path_buf(),
        mandates_dir,
        hooks_dir,
        templates_dir,
        ledger_path: state_dir.join("handfest-ledger.sqlite"),
        policy_map_path: dir.join("policy-map.json"),
        profile_path: dir.join("profile.json"),
    })
}

#[cfg(unix)]
fn set_dir_mode_0700(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to set mode 0700 on '{}': {err}", dir.display()))
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_dir: &Path) -> Result<(), String> {
    Ok(())
}

fn init_or_verify_ledger(ledger_path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(ledger_path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(format!(
                    "existing ledger path '{}' is not a regular file",
                    ledger_path.display()
                ));
            }
            let ledger = SqliteLedger::open_existing(ledger_path).map_err(|err| {
                format!(
                    "failed to verify existing ledger '{}': {err}",
                    ledger_path.display()
                )
            })?;
            let _ = ledger.verify_integrity().map_err(|err| {
                format!(
                    "existing ledger '{}' failed integrity verification: {err}",
                    ledger_path.display()
                )
            })?;
            let stored = ledger.list_stored_revocations().map_err(|err| {
                format!(
                    "failed to read revocations from existing ledger '{}': {err}",
                    ledger_path.display()
                )
            })?;
            verify_stored_revocations_signatures(&stored).map_err(|err| {
                format!(
                    "existing ledger '{}' failed revocation signature verification: {err}",
                    ledger_path.display()
                )
            })?;
            Ok(false)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let ledger = SqliteLedger::open(ledger_path).map_err(|err| {
                format!(
                    "failed to initialize ledger '{}': {err}",
                    ledger_path.display()
                )
            })?;
            let _ = ledger.verify_integrity().map_err(|err| {
                format!(
                    "newly initialized ledger '{}' failed integrity check: {err}",
                    ledger_path.display()
                )
            })?;
            Ok(true)
        }
        Err(err) => Err(format!(
            "failed to inspect ledger path '{}': {err}",
            ledger_path.display()
        )),
    }
}

fn load_or_create_agent_key(
    dir: &Path,
    explicit_agent_key: Option<&Path>,
) -> Result<(PathBuf, KeyId, bool), String> {
    if let Some(path) = explicit_agent_key {
        let abs_path = absolutize_lexical_path(path)?;
        let key_id = load_ed25519_key_id(&abs_path)?;
        set_file_mode_0600(&abs_path)?;
        return Ok((abs_path, key_id, false));
    }

    let default_path = dir.join("agent.key.json");
    match fs::symlink_metadata(&default_path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(format!(
                    "existing agent key path '{}' is not a regular file",
                    default_path.display()
                ));
            }
            let key_id = load_ed25519_key_id(&default_path)?;
            set_file_mode_0600(&default_path)?;
            Ok((default_path, key_id, false))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let keypair = Ed25519Keypair::generate();
            let key_file = keypair.to_key_file();
            let json_text = serde_json::to_string_pretty(&key_file)
                .map_err(|err| format!("serialize error: {err}"))?;
            write_new_secret_file(&default_path, &format!("{json_text}\n"))?;
            Ok((default_path, keypair.key_id(), true))
        }
        Err(err) => Err(format!(
            "failed to inspect agent key path '{}': {err}",
            default_path.display()
        )),
    }
}

#[cfg(unix)]
fn set_file_mode_0600(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to set mode 0600 on '{}': {err}", path.display()))
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn load_ed25519_key_id(path: &Path) -> Result<KeyId, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read agent key '{}': {err}", path.display()))?;
    let key_file: Ed25519KeyFile = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid agent key JSON in '{}': {err}", path.display()))?;
    let keypair = Ed25519Keypair::from_key_file(&key_file)
        .map_err(|err| format!("failed to load agent key '{}': {err}", path.display()))?;
    Ok(keypair.key_id())
}

#[cfg(unix)]
fn write_new_secret_file(path: &Path, content: &str) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let mut staged = None;
    for attempt in 0u32..64 {
        let tmp_path = parent.join(format!(".handfest-secret-{pid}-{attempt}.tmp"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => {
                staged = Some((tmp_path, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "failed to create staged secret file in '{}': {err}",
                    parent.display()
                ));
            }
        }
    }
    let (tmp_path, mut file) = staged.ok_or_else(|| {
        format!(
            "failed to allocate unique staged secret file in '{}'",
            parent.display()
        )
    })?;

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
    let link_res = fs::hard_link(&tmp_path, path);
    let _ = fs::remove_file(&tmp_path);
    link_res.map_err(|err| format!("failed to install secret file '{}': {err}", path.display()))
}

#[cfg(not(unix))]
fn write_new_secret_file(path: &Path, content: &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("failed to create secret file '{}': {err}", path.display()))?;
    if let Err(err) = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("failed to write '{}': {err}", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
fn write_public_file(path: &Path, content: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let (tmp_path, mut file) = create_unique_public_temp(parent, pid)?;

    let write_res = (|| -> std::io::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
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
fn create_unique_public_temp(parent: &Path, pid: u32) -> Result<(PathBuf, fs::File), String> {
    use std::os::unix::fs::OpenOptionsExt;

    for attempt in 0u32..64 {
        let tmp_path = parent.join(format!(".handfest-profile-{pid}-{attempt}.tmp"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "failed to create temporary profile file in '{}': {err}",
                    parent.display()
                ));
            }
        }
    }
    Err(format!(
        "failed to allocate unique temporary profile file in '{}'",
        parent.display()
    ))
}

#[cfg(not(unix))]
fn write_public_file(path: &Path, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|err| format!("failed to write '{}': {err}", path.display()))
}

fn format_next_step_sign_command(
    mandates_dir: &str,
    signer_kind: SignerKind,
    signer_hint: &str,
) -> String {
    let draft = format!("{mandates_dir}/draft.hf");
    let out = format!("{mandates_dir}/root.signed.json");
    let flag = signer_kind.sign_flag();
    let signer_arg = if signer_hint.starts_with('-') {
        format!("{flag}={}", shell_quote(signer_hint))
    } else {
        format!("{flag} {}", shell_quote(signer_hint))
    };
    format!(
        "handfest sign --mandate {} {signer_arg} --valid-from <RFC3339-UTC> --valid-until <RFC3339-UTC> --out {}",
        shell_quote(&draft),
        shell_quote(&out),
    )
}

fn shell_quote(raw: &str) -> String {
    if !raw.is_empty()
        && raw.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b':' | b'+')
        })
    {
        return raw.to_string();
    }
    let escaped = raw.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
