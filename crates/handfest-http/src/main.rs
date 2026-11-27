//! `handfest-http` binary: fail-closed loopback HTTP/REST Policy Enforcement Point enforcing
//! `HANDFEST v1` mandate chains, typed facts, tamper-evident receipts, and credential injection.

use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::Parser;
use handfest_anchors::AnchorRegistry;
use handfest_core::ast::KeyId;
use handfest_core::exact_json::write_json_string;
use handfest_http::{
    load_http_policy_map_file, verify_mandate_chain_with, verify_revocations_with,
    AutoUpstreamTransport, HttpPolicyError, HttpProxy, HttpProxyError, DEFAULT_TIMEOUT_SECS,
};
use handfest_ledger::SqliteLedger;
use handfest_pep::{
    load_signed_mandates_files, load_signed_revocations_files, PepError, RuntimeClock,
};

#[derive(Debug, Parser)]
#[command(
    name = "handfest-http",
    version,
    about = "Fail-closed loopback HTTP/REST proxy enforcing HANDFEST v1 mandate chains"
)]
struct Cli {
    /// Loopback socket address to listen on (e.g. 127.0.0.1:8080).
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,

    /// Path to the SQLite receipt and quota ledger database.
    #[arg(long)]
    ledger: PathBuf,

    /// Ordered signed mandate JSON files (root first, leaf last).
    #[arg(long, required = true, num_args = 1..)]
    chain: Vec<PathBuf>,

    /// Concrete requesting actor KeyId (e.g. ed25519:<hex>).
    #[arg(long)]
    actor_key: String,

    /// Path to the JSON HttpPolicyMap file.
    #[arg(long)]
    policy_map: PathBuf,

    /// Optional signed revocation JSON files enforced alongside persisted ledger revocations (repeatable).
    #[arg(long = "revocation")]
    revocations: Vec<PathBuf>,

    /// Upstream connect/request timeout in seconds (must be >= 1).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,

    /// Optional fixed UTC evaluation timestamp in RFC 3339 format (YYYY-MM-DDTHH:MM:SSZ).
    #[arg(long)]
    now: Option<String>,
}

/// Typed startup and runtime errors emitted as structured single-line JSON on `stderr`.
#[derive(Debug, PartialEq, Eq)]
enum StartupError {
    CliArgs(String),
    ChainIo(String),
    ChainInvalid(String),
    PolicyIo(String),
    PolicyInvalid(String),
    LedgerOpen(String),
    BindFailed(String),
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
            Self::BindFailed(_) => "bind_failed",
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
            | Self::BindFailed(msg)
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
    let bind_addr = parse_loopback_bind(&cli.bind)?;
    let mut proxy = build_proxy(&cli)?;
    let listener = TcpListener::bind(bind_addr).map_err(|err| {
        StartupError::BindFailed(format!(
            "failed to bind loopback address {bind_addr}: {err}"
        ))
    })?;
    proxy
        .serve_listener(listener)
        .map_err(|err| StartupError::RuntimeError(err.to_string()))
}

fn parse_loopback_bind(raw: &str) -> Result<SocketAddr, StartupError> {
    let addr: SocketAddr = raw
        .parse()
        .map_err(|err| StartupError::CliArgs(format!("invalid --bind '{raw}': {err}")))?;
    if !addr.ip().is_loopback() {
        return Err(StartupError::CliArgs(format!(
            "--bind '{raw}' must be a loopback address (e.g. 127.0.0.1:8080)"
        )));
    }
    Ok(addr)
}

fn build_proxy(
    cli: &Cli,
) -> Result<HttpProxy<RuntimeClock, SqliteLedger, AutoUpstreamTransport>, StartupError> {
    if cli.timeout_secs == 0 {
        return Err(StartupError::CliArgs(
            "--timeout-secs must be >= 1".to_string(),
        ));
    }

    let signed_chain = load_signed_mandates_files(&cli.chain).map_err(map_envelope_load_error)?;
    let verifier = AnchorRegistry::default_registry();
    let verified_chain = verify_mandate_chain_with(&verifier, &signed_chain).map_err(|err| {
        StartupError::ChainInvalid(format!("startup mandate chain verification failed: {err}"))
    })?;
    let signed_revocations =
        load_signed_revocations_files(&cli.revocations).map_err(map_envelope_load_error)?;
    let verified_revocations =
        verify_revocations_with(&verifier, &signed_revocations).map_err(|err| {
            StartupError::ChainInvalid(format!("startup revocation verification failed: {err}"))
        })?;

    let actor_key = KeyId::parse(&cli.actor_key).map_err(|err| {
        StartupError::CliArgs(format!("invalid --actor-key '{}': {err}", cli.actor_key))
    })?;

    let policy_map = load_http_policy_map_file(&cli.policy_map).map_err(|err| match err {
        HttpPolicyError::Io(msg) => {
            StartupError::PolicyIo(format!("failed to load --policy-map: {msg}"))
        }
        other => StartupError::PolicyInvalid(format!("failed to load --policy-map: {other}")),
    })?;

    let clock = RuntimeClock::from_optional_rfc3339(cli.now.as_deref()).map_err(|err| {
        StartupError::CliArgs(format!(
            "invalid --now '{}': {err}",
            cli.now.as_deref().unwrap_or("")
        ))
    })?;

    let ledger = SqliteLedger::open(&cli.ledger).map_err(|err| {
        StartupError::LedgerOpen(format!(
            "failed to open ledger '{}': {err}",
            cli.ledger.display()
        ))
    })?;

    let transport = AutoUpstreamTransport::with_timeout_secs(cli.timeout_secs)
        .map_err(|err| StartupError::CliArgs(err.to_string()))?;

    HttpProxy::new(
        verified_chain,
        actor_key,
        policy_map,
        ledger,
        clock,
        transport,
    )
    .map(|proxy| proxy.with_revocations(verified_revocations))
    .map_err(|err| match err {
        HttpProxyError::Policy(policy_err) => {
            StartupError::PolicyInvalid(format!("failed to initialize HTTP proxy: {policy_err}"))
        }
        HttpProxyError::Pep(pep_err) => {
            StartupError::ChainInvalid(format!("failed to initialize HTTP proxy: {pep_err}"))
        }
        other => StartupError::RuntimeError(format!("failed to initialize HTTP proxy: {other}")),
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
            (StartupError::ChainIo("missing".into()), "chain_io"),
            (
                StartupError::ChainInvalid("bad sig".into()),
                "chain_invalid",
            ),
            (StartupError::PolicyIo("missing".into()), "policy_io"),
            (
                StartupError::PolicyInvalid("bad route".into()),
                "policy_invalid",
            ),
            (StartupError::LedgerOpen("locked".into()), "ledger_open"),
            (StartupError::BindFailed("in use".into()), "bind_failed"),
            (StartupError::RuntimeError("boom".into()), "runtime_error"),
        ];
        for (err, expected_code) in cases {
            let line = err.to_json_line();
            assert!(!line.contains('\n'));
            let parsed = parse_exact_json(&line).expect("valid JSON");
            let obj = parsed.as_object().expect("JSON object");
            assert_eq!(
                obj.get("error"),
                Some(&ExactJson::Str("startup_failed".into()))
            );
            assert_eq!(obj.get("code"), Some(&ExactJson::Str(expected_code.into())));
            assert_eq!(
                obj.get("message"),
                Some(&ExactJson::Str(err.message().into()))
            );
        }
    }

    #[test]
    fn parse_loopback_bind_accepts_loopback_and_rejects_wildcard() {
        assert!(parse_loopback_bind("127.0.0.1:8080").is_ok());
        assert!(parse_loopback_bind("[::1]:8080").is_ok());
        let err = parse_loopback_bind("0.0.0.0:8080").expect_err("non-loopback must fail");
        assert!(matches!(err, StartupError::CliArgs(_)));
        let err2 = parse_loopback_bind("not-an-addr").expect_err("bad addr must fail");
        assert!(matches!(err2, StartupError::CliArgs(_)));
    }

    struct StartupFixture {
        dir: tempfile::TempDir,
        chain_path: PathBuf,
        corrupt_json: PathBuf,
        bad_sig_chain: PathBuf,
        bad_sig_rev: PathBuf,
        policy_path: PathBuf,
        bad_policy_path: PathBuf,
        ledger_path: PathBuf,
        actor_key: String,
    }

    impl StartupFixture {
        fn new() -> Self {
            use std::collections::BTreeMap;

            use handfest_anchors::Ed25519Keypair;
            use handfest_core::ast::ActorDecl;
            use handfest_core::cnl::{parse_mandate, render_canonical};
            use handfest_core::revocation::{
                render_canonical_revocation, RevocationAst, RevocationTarget,
            };
            use handfest_core::ActorKind;

            let dir = tempfile::TempDir::new().expect("tempdir");
            let root_kp = Ed25519Keypair::generate();
            let agent_kp = Ed25519Keypair::generate();
            let text = format!(
                "HANDFEST v1\n\
                 FROM human \"Owner\" (key: {})\n\
                 TO agent \"Runner\" (key: {})\n\
                 DELEGATION max 0 hops\n\
                 ALLOW api.read\n\
                 ON item \"*\"\n",
                root_kp.key_id(),
                agent_kp.key_id()
            );
            let ast = parse_mandate(&text).expect("mandate");
            let mandate_id = ast.mandate_id();
            let signed = root_kp
                .sign_mandate(
                    &render_canonical(&ast),
                    "anchor:local",
                    1_760_000_000,
                    1_760_086_400,
                )
                .expect("sign");

            let chain_path = dir.path().join("chain.json");
            std::fs::write(&chain_path, serde_json::to_string(&signed).unwrap()).unwrap();

            let mut bad_signed = signed;
            bad_signed.signature_hex = "00".repeat(64);
            let bad_sig_chain = dir.path().join("bad_sig_chain.json");
            std::fs::write(&bad_sig_chain, serde_json::to_string(&bad_signed).unwrap()).unwrap();

            let by = ActorDecl::new(ActorKind::Human, "Owner", root_kp.key_id(), BTreeMap::new())
                .unwrap();
            let rev_ast = RevocationAst::new(
                by,
                RevocationTarget::Mandate(mandate_id),
                1_760_000_000,
                Some("revoked".to_string()),
            )
            .unwrap();
            let mut bad_rev = root_kp
                .sign_revocation(
                    &render_canonical_revocation(&rev_ast),
                    "anchor:local",
                    1_760_000_000,
                    1_760_086_400,
                )
                .expect("sign revocation");
            bad_rev.signature_hex = "00".repeat(64);
            let bad_sig_rev = dir.path().join("bad_sig_rev.json");
            std::fs::write(&bad_sig_rev, serde_json::to_string(&bad_rev).unwrap()).unwrap();

            let corrupt_json = dir.path().join("corrupt.json");
            std::fs::write(&corrupt_json, "{not json").unwrap();

            let policy_path = dir.path().join("policy.json");
            std::fs::write(
                &policy_path,
                r#"{"upstream_base_url":"http://127.0.0.1:9","routes":[{"method":"GET","path_template":"/v1/items/{id}","action":"api.read","resource_kind":"item","resource_id":{"path_param":"id"}}]}"#,
            )
            .unwrap();
            let bad_policy_path = dir.path().join("bad_policy.json");
            std::fs::write(&bad_policy_path, "{bad").unwrap();

            Self {
                ledger_path: dir.path().join("ledger.sqlite"),
                actor_key: agent_kp.key_id().to_string(),
                dir,
                chain_path,
                corrupt_json,
                bad_sig_chain,
                bad_sig_rev,
                policy_path,
                bad_policy_path,
            }
        }

        fn base_cli(&self) -> Cli {
            Cli {
                bind: "127.0.0.1:0".to_string(),
                ledger: self.ledger_path.clone(),
                chain: vec![self.chain_path.clone()],
                actor_key: self.actor_key.clone(),
                policy_map: self.policy_path.clone(),
                revocations: Vec::new(),
                timeout_secs: 5,
                now: None,
            }
        }
    }

    #[test]
    fn build_proxy_rejects_invalid_cli_args_policy_and_ledger_paths() {
        let fx = StartupFixture::new();

        let mut c = fx.base_cli();
        c.timeout_secs = 0;
        assert!(matches!(build_proxy(&c), Err(StartupError::CliArgs(_))));

        let mut c = fx.base_cli();
        c.actor_key = "not-a-key".to_string();
        assert!(matches!(build_proxy(&c), Err(StartupError::CliArgs(_))));

        let mut c = fx.base_cli();
        c.now = Some("not-a-timestamp".to_string());
        assert!(matches!(build_proxy(&c), Err(StartupError::CliArgs(_))));

        let mut c = fx.base_cli();
        c.policy_map = fx.dir.path().join("no-policy.json");
        assert!(matches!(build_proxy(&c), Err(StartupError::PolicyIo(_))));

        let mut c = fx.base_cli();
        c.policy_map = fx.bad_policy_path.clone();
        assert!(matches!(
            build_proxy(&c),
            Err(StartupError::PolicyInvalid(_))
        ));

        let mut c = fx.base_cli();
        c.ledger = fx.dir.path().join("nonexistent-dir").join("ledger.sqlite");
        assert!(matches!(build_proxy(&c), Err(StartupError::LedgerOpen(_))));
    }

    #[test]
    fn build_proxy_rejects_missing_corrupt_and_bad_signature_chains_and_revocations() {
        let fx = StartupFixture::new();

        let mut c = fx.base_cli();
        c.chain = vec![fx.dir.path().join("missing.json")];
        assert!(matches!(build_proxy(&c), Err(StartupError::ChainIo(_))));

        let mut c = fx.base_cli();
        c.chain = vec![fx.corrupt_json.clone()];
        assert!(matches!(
            build_proxy(&c),
            Err(StartupError::ChainInvalid(_))
        ));

        let mut c = fx.base_cli();
        c.chain = vec![fx.bad_sig_chain.clone()];
        assert!(matches!(
            build_proxy(&c),
            Err(StartupError::ChainInvalid(ref msg)) if msg.contains("mandate chain verification failed")
        ));

        let mut c = fx.base_cli();
        c.revocations = vec![fx.dir.path().join("missing-rev.json")];
        assert!(matches!(build_proxy(&c), Err(StartupError::ChainIo(_))));

        let mut c = fx.base_cli();
        c.revocations = vec![fx.corrupt_json.clone()];
        assert!(matches!(
            build_proxy(&c),
            Err(StartupError::ChainInvalid(_))
        ));

        let mut c = fx.base_cli();
        c.revocations = vec![fx.bad_sig_rev.clone()];
        assert!(matches!(
            build_proxy(&c),
            Err(StartupError::ChainInvalid(ref msg)) if msg.contains("revocation verification failed")
        ));
    }

    #[test]
    fn build_proxy_succeeds_and_run_reports_bind_failure_on_occupied_port() {
        let fx = StartupFixture::new();
        assert!(build_proxy(&fx.base_cli()).is_ok());
        use handfest_pep::{Clock, FixedClock, SystemClock};
        assert!(RuntimeClock::System(SystemClock).now_unix() > 1_700_000_000);
        assert_eq!(RuntimeClock::Fixed(FixedClock::new(77)).now_unix(), 77);
        assert_eq!(
            StartupError::BindFailed("occupied".into()).to_string(),
            "bind_failed: occupied"
        );

        let blocker = TcpListener::bind("127.0.0.1:0").expect("bind blocker");
        let occupied_addr = blocker.local_addr().unwrap();
        let mut c = fx.base_cli();
        c.bind = occupied_addr.to_string();
        assert!(matches!(run(c), Err(StartupError::BindFailed(_))));
    }
}
