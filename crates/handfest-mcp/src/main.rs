//! `handfest-mcp` binary: fail-closed MCP stdio JSON-RPC 2.0 mandate proxy.

use std::fs;
use std::io::{self, BufReader, BufWriter};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;

use clap::Parser;
use handfest_anchors::{AnchorRegistry, SignedMandate};
use handfest_core::ast::{parse_rfc3339_utc, KeyId};
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain_with, Clock, FixedClock, McpProxy, SystemClock, ToolPolicyMap,
};

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

    /// Upstream MCP server command and arguments (passed after `--`).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    upstream: Vec<String>,
}

enum RuntimeClock {
    System(SystemClock),
    Fixed(FixedClock),
}

impl Clock for RuntimeClock {
    fn now_unix(&self) -> i64 {
        match self {
            Self::System(c) => c.now_unix(),
            Self::Fixed(c) => c.now_unix(),
        }
    }
}

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
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("handfest-mcp error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let (upstream_cmd, upstream_args) = cli
        .upstream
        .split_first()
        .ok_or_else(|| "missing upstream MCP server command".to_string())?;
    if upstream_cmd.is_empty() {
        return Err("upstream MCP server command must not be empty".to_string());
    }

    let signed_chain = load_signed_mandates(&cli.chain)?;
    let verifier = AnchorRegistry::default_registry();
    let verified_chain = verify_mandate_chain_with(&verifier, &signed_chain)
        .map_err(|err| format!("startup mandate chain verification failed: {err}"))?;

    let actor_key = KeyId::parse(&cli.actor_key)
        .map_err(|err| format!("invalid --actor-key '{}': {err}", cli.actor_key))?;

    let policy_map = ToolPolicyMap::from_file(&cli.policy_map)
        .map_err(|err| format!("failed to load --policy-map: {err}"))?;

    let clock = match &cli.now {
        Some(raw) => {
            let ts =
                parse_rfc3339_utc(raw).map_err(|err| format!("invalid --now '{raw}': {err}"))?;
            RuntimeClock::Fixed(FixedClock::new(ts))
        }
        None => RuntimeClock::System(SystemClock),
    };

    let ledger = SqliteLedger::open(&cli.ledger)
        .map_err(|err| format!("failed to open ledger '{}': {err}", cli.ledger.display()))?;

    let mut proxy = McpProxy::new(verified_chain, actor_key, policy_map, ledger, clock)
        .map_err(|err| format!("failed to initialize MCP proxy: {err}"))?;

    let mut child = Command::new(upstream_cmd)
        .args(upstream_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| format!("failed to spawn upstream '{upstream_cmd}': {err}"))?;

    let upstream_in = child
        .stdin
        .take()
        .ok_or_else(|| "failed to capture upstream stdin pipe".to_string())?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture upstream stdout pipe".to_string())?;
    let mut guard = ChildGuard::new(child);

    let client_in = BufReader::new(io::stdin());
    let stdout = io::stdout();
    let mut client_out = BufWriter::new(stdout.lock());
    let upstream_out = BufReader::new(child_stdout);

    let run_result = proxy.run(client_in, &mut client_out, upstream_in, upstream_out);
    guard.shutdown(run_result.is_ok());

    run_result.map_err(|err| err.to_string())
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
