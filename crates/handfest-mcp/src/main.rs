//! `handfest-mcp` binary: fail-closed MCP stdio JSON-RPC 2.0 mandate proxy.

use std::fmt;
use std::io::{self, BufReader, BufWriter};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::Parser;
use handfest_anchors::AnchorRegistry;
use handfest_core::ast::KeyId;
use handfest_core::exact_json::write_json_string;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{verify_revocations_with, MappingError, McpProxy, ProxyError};
use handfest_pep::{load_signed_revocations_files, PepError, RuntimeClock};

const CHILD_EXIT_GRACE_POLLS: usize = 20;
const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Parser)]
#[command(
    name = "handfest-mcp",
    version,
    about = "Drop-in MCP stdio JSON-RPC 2.0 proxy enforcing HANDFEST v1 mandate chains"
)]
struct Cli {
    /// Ordered signed mandate JSON files (root first, leaf last).
    #[arg(long, required = true, num_args = 1..)]
    chain: Vec<PathBuf>,

    /// Path to the SQLite receipt and quota ledger database.
    #[arg(long)]
    ledger: PathBuf,

    /// Concrete requesting actor KeyId (e.g. ed25519:<hex>).
    #[arg(long)]
    actor_key: String,

    /// Path to the JSON ToolPolicyMap file.
    #[arg(long)]
    policy_map: PathBuf,

    /// Optional fixed UTC evaluation timestamp in RFC 3339 format (YYYY-MM-DDTHH:MM:SSZ).
    #[arg(long)]
    now: Option<String>,

    /// Optional signed revocation JSON files enforced alongside persisted ledger revocations (repeatable).
    #[arg(long = "revocation")]
    revocations: Vec<PathBuf>,

    /// Upstream MCP server command and arguments (passed after `--`).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    upstream: Vec<String>,
}

/// Typed startup and runtime errors emitted as structured JSON on `stderr`.
#[derive(Debug, PartialEq, Eq)]
enum StartupError {
    CliArgs(String),
    ChainIo(String),
    ChainInvalid(String),
    PolicyIo(String),
    PolicyInvalid(String),
    LedgerOpen(String),
    UpstreamSpawn(String),
    RuntimeError(String),
}

impl StartupError {
    const fn code(&self) -> &'static str {
        match self {
            Self::CliArgs(_) => "cli_args",
            Self::ChainIo(_) => "chain_io",
            Self::ChainInvalid(_) => "chain_invalid",
            Self::PolicyIo(_) => "policy_io",
            Self::PolicyInvalid(_) => "policy_invalid",
            Self::LedgerOpen(_) => "ledger_open",
            Self::UpstreamSpawn(_) => "upstream_spawn",
            Self::RuntimeError(_) => "runtime_error",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::CliArgs(msg)
            | Self::ChainIo(msg)
            | Self::ChainInvalid(msg)
            | Self::PolicyIo(msg)
            | Self::PolicyInvalid(msg)
            | Self::LedgerOpen(msg)
            | Self::UpstreamSpawn(msg)
            | Self::RuntimeError(msg) => msg,
        }
    }

    fn to_json_line(&self) -> String {
        let mut out = String::from(r#"{"error":"startup_failed","code":"#);
        write_json_string(self.code(), &mut out);
        out.push_str(r#","message":"#);
        write_json_string(self.message(), &mut out);
        out.push('}');
        out
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for StartupError {}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn shutdown(&mut self, graceful: bool) {
        if self.reaped {
            return;
        }
        if graceful {
            for _ in 0..CHILD_EXIT_GRACE_POLLS {
                match self.child.try_wait() {
                    Ok(Some(_)) => {
                        self.reaped = true;
                        return;
                    }
                    Ok(None) => thread::sleep(CHILD_EXIT_POLL_INTERVAL),
                    Err(_) => break,
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.shutdown(false);
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = err.print();
                return ExitCode::SUCCESS;
            }
            let startup_err = StartupError::CliArgs(err.to_string().trim().to_string());
            eprintln!("{}", startup_err.to_json_line());
            return ExitCode::FAILURE;
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{}", err.to_json_line());
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), StartupError> {
    let (upstream_cmd, upstream_args) = parse_upstream_command(&cli.upstream)?;
    let mut proxy = build_proxy(&cli)?;

    let mut child = Command::new(upstream_cmd)
        .args(upstream_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| {
            StartupError::UpstreamSpawn(format!("failed to spawn upstream '{upstream_cmd}': {err}"))
        })?;

    let upstream_in = child.stdin.take().ok_or_else(|| {
        StartupError::UpstreamSpawn("failed to capture upstream stdin pipe".to_string())
    })?;
    let child_stdout = child.stdout.take().ok_or_else(|| {
        StartupError::UpstreamSpawn("failed to capture upstream stdout pipe".to_string())
    })?;
    let mut guard = ChildGuard::new(child);

    let client_in = BufReader::new(io::stdin());
    let stdout = io::stdout();
    let mut client_out = BufWriter::new(stdout.lock());
    let upstream_out = BufReader::new(child_stdout);

    let run_result = proxy.run(client_in, &mut client_out, upstream_in, upstream_out);
    guard.shutdown(run_result.is_ok());

    run_result.map_err(|err| StartupError::RuntimeError(err.to_string()))
}

fn parse_upstream_command(upstream: &[String]) -> Result<(&str, &[String]), StartupError> {
    let (cmd, args) = upstream
        .split_first()
        .ok_or_else(|| StartupError::CliArgs("missing upstream MCP server command".to_string()))?;
    if cmd.is_empty() {
        return Err(StartupError::CliArgs(
            "upstream MCP server command must not be empty".to_string(),
        ));
    }
    Ok((cmd.as_str(), args))
}

fn build_proxy(cli: &Cli) -> Result<McpProxy<RuntimeClock, SqliteLedger>, StartupError> {
    let actor_key = KeyId::parse(&cli.actor_key).map_err(|err| {
        StartupError::CliArgs(format!("invalid --actor-key '{}': {err}", cli.actor_key))
    })?;
    let clock = RuntimeClock::from_optional_rfc3339(cli.now.as_deref()).map_err(|err| {
        StartupError::CliArgs(format!(
            "invalid --now '{}': {err}",
            cli.now.as_deref().unwrap_or("")
        ))
    })?;
    let verifier = AnchorRegistry::default_registry();
    let signed_revocations =
        load_signed_revocations_files(&cli.revocations).map_err(map_envelope_load_error)?;
    let verified_revocations =
        verify_revocations_with(&verifier, &signed_revocations).map_err(|err| {
            StartupError::ChainInvalid(format!("startup revocation verification failed: {err}"))
        })?;
    let policy_map =
        handfest_mcp::mapping::load_policy_map_file(&cli.policy_map).map_err(|err| match err {
            MappingError::Io(msg) => {
                StartupError::PolicyIo(format!("failed to load --policy-map: {msg}"))
            }
            other => StartupError::PolicyInvalid(format!("failed to load --policy-map: {other}")),
        })?;
    let ledger = SqliteLedger::open(&cli.ledger).map_err(|err| {
        StartupError::LedgerOpen(format!(
            "failed to open ledger '{}': {err}",
            cli.ledger.display()
        ))
    })?;

    McpProxy::from_chain_files(cli.chain.clone(), actor_key, policy_map, ledger, clock)
        .map(|proxy| proxy.with_revocations(verified_revocations))
        .map_err(|err| match err {
            ProxyError::Io(io_err) => StartupError::ChainIo(io_err.to_string()),
            ProxyError::Mapping(map_err) => {
                StartupError::PolicyInvalid(format!("failed to initialize MCP proxy: {map_err}"))
            }
            ProxyError::InvalidChain(_) | ProxyError::Anchor(_) | ProxyError::ChainStructure(_) => {
                StartupError::ChainInvalid(format!(
                    "startup mandate chain verification failed: {err}"
                ))
            }
            other => StartupError::RuntimeError(format!("failed to initialize MCP proxy: {other}")),
        })
}

fn map_envelope_load_error(err: PepError) -> StartupError {
    match err {
        PepError::Io(io_err) => StartupError::ChainIo(io_err.to_string()),
        other => StartupError::ChainInvalid(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_core::exact_json::{parse_exact_json, ExactJson};

    #[test]
    fn startup_error_emits_distinct_codes_and_valid_escaped_json() {
        let cases = [
            (
                StartupError::CliArgs("bad \"flag\"\nline2".into()),
                "cli_args",
            ),
            (StartupError::ChainIo("missing chain".into()), "chain_io"),
            (
                StartupError::ChainInvalid("bad sig".into()),
                "chain_invalid",
            ),
            (StartupError::PolicyIo("missing policy".into()), "policy_io"),
            (
                StartupError::PolicyInvalid("bad policy".into()),
                "policy_invalid",
            ),
            (
                StartupError::LedgerOpen("cannot open db".into()),
                "ledger_open",
            ),
            (
                StartupError::UpstreamSpawn("no binary".into()),
                "upstream_spawn",
            ),
            (StartupError::RuntimeError("eof".into()), "runtime_error"),
        ];
        for (err, expected_code) in cases {
            assert_eq!(err.code(), expected_code);
            assert!(err.to_string().starts_with(expected_code));
            let line = err.to_json_line();
            assert!(!line.contains('\n'), "JSON error line must be single-line");
            let parsed = parse_exact_json(&line).expect("valid RFC 8259 JSON");
            let obj = parsed.as_object().expect("top-level JSON object");
            assert_eq!(obj.len(), 3);
            assert_eq!(
                obj.get("error"),
                Some(&ExactJson::Str("startup_failed".to_string()))
            );
            assert_eq!(
                obj.get("code"),
                Some(&ExactJson::Str(expected_code.to_string()))
            );
            assert_eq!(
                obj.get("message"),
                Some(&ExactJson::Str(err.message().to_string()))
            );
        }
    }

    #[test]
    fn parse_upstream_command_rejects_empty_slice_and_empty_cmd() {
        assert_eq!(
            parse_upstream_command(&[]),
            Err(StartupError::CliArgs(
                "missing upstream MCP server command".to_string()
            ))
        );
        assert_eq!(
            parse_upstream_command(&[String::new()]),
            Err(StartupError::CliArgs(
                "upstream MCP server command must not be empty".to_string()
            ))
        );
        assert_eq!(
            parse_upstream_command(&["sh".to_string(), "-c".to_string()]),
            Ok(("sh", &["-c".to_string()][..]))
        );
    }
}
