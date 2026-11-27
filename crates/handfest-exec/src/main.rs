//! `handfest-exec` binary: fail-closed CLI Policy Enforcement Point for `HANDFEST v1` mandates.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::Parser;
use handfest_anchors::AnchorRegistry;
use handfest_core::ast::KeyId;
use handfest_core::exact_json::write_json_string;
use handfest_exec::{
    load_cli_policy_map_file, verify_mandate_chain_with, verify_revocations_with, ExecOutcome,
    ExecProxy, GateEngine, OsCommandExecutor, PolicyError, ProxyError,
};
use handfest_ledger::SqliteLedger;
use handfest_pep::{
    load_signed_mandates_files, load_signed_revocations_files, PepError, RuntimeClock,
};

#[derive(Debug, Parser)]
#[command(
    name = "handfest-exec",
    version,
    about = "Fail-closed CLI Policy Enforcement Point enforcing HANDFEST v1 mandates without a shell"
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

    /// Path to the JSON CliPolicyMap file.
    #[arg(long)]
    policy_map: PathBuf,

    /// Optional fixed UTC evaluation timestamp in RFC 3339 format (YYYY-MM-DDTHH:MM:SSZ).
    #[arg(long)]
    now: Option<String>,

    /// Optional signed revocation JSON files enforced alongside persisted ledger revocations (repeatable).
    #[arg(long = "revocation")]
    revocations: Vec<PathBuf>,

    /// Logical command name defined in the CliPolicyMap.
    #[arg(long)]
    command: String,

    /// Caller flags passed strictly after `--`.
    #[arg(last = true)]
    args: Vec<String>,
}

/// Typed startup and runtime errors emitted as structured single-line JSON on `stderr`.
#[derive(Debug, PartialEq, Eq)]
enum CliError {
    CliArgs(String),
    ChainIo(String),
    ChainInvalid(String),
    PolicyIo(String),
    PolicyInvalid(String),
    LedgerOpen(String),
    SecretLoad(String),
    ExecFailed(String),
    RuntimeError(String),
}

impl CliError {
    const fn code(&self) -> &'static str {
        match self {
            Self::CliArgs(_) => "cli_args",
            Self::ChainIo(_) => "chain_io",
            Self::ChainInvalid(_) => "chain_invalid",
            Self::PolicyIo(_) => "policy_io",
            Self::PolicyInvalid(_) => "policy_invalid",
            Self::LedgerOpen(_) => "ledger_open",
            Self::SecretLoad(_) => "secret_load",
            Self::ExecFailed(_) => "exec_failed",
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
            | Self::SecretLoad(msg)
            | Self::ExecFailed(msg)
            | Self::RuntimeError(msg) => msg,
        }
    }

    fn to_json_line(&self) -> String {
        let mut out = String::from(r#"{"error":"exec_error","code":"#);
        write_json_string(self.code(), &mut out);
        out.push_str(r#","message":"#);
        write_json_string(self.message(), &mut out);
        out.push('}');
        out
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for CliError {}

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
            let cli_err = CliError::CliArgs(err.to_string().trim().to_string());
            let _ = writeln!(io::stderr().lock(), "{}", cli_err.to_json_line());
            return ExitCode::FAILURE;
        }
    };

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            let _ = writeln!(io::stderr().lock(), "{}", err.to_json_line());
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, CliError> {
    let mut proxy = build_proxy(&cli)?;
    let outcome = proxy
        .execute(&cli.command, &cli.args)
        .map_err(map_proxy_error)?;

    match outcome {
        ExecOutcome::Permitted { output, .. } => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(&output.stdout)
                .and_then(|()| stdout.flush())
                .map_err(|err| CliError::RuntimeError(format!("stdout write failed: {err}")))?;
            let mut stderr = io::stderr().lock();
            stderr
                .write_all(&output.stderr)
                .and_then(|()| stderr.flush())
                .map_err(|err| CliError::RuntimeError(format!("stderr write failed: {err}")))?;
            Ok(exit_code_from_i32(output.exit_code))
        }
        ExecOutcome::Denied { reason, receipt } => {
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                format_denied_json(&reason, &receipt.receipt_hash.to_string())
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

fn build_proxy(
    cli: &Cli,
) -> Result<ExecProxy<RuntimeClock, SqliteLedger, OsCommandExecutor>, CliError> {
    let signed_chain = load_signed_mandates_files(&cli.chain).map_err(map_envelope_load_error)?;
    let verifier = AnchorRegistry::default_registry();
    let verified_chain = verify_mandate_chain_with(&verifier, &signed_chain).map_err(|err| {
        CliError::ChainInvalid(format!("startup mandate chain verification failed: {err}"))
    })?;
    let signed_revocations =
        load_signed_revocations_files(&cli.revocations).map_err(map_envelope_load_error)?;
    let verified_revocations =
        verify_revocations_with(&verifier, &signed_revocations).map_err(|err| {
            CliError::ChainInvalid(format!("startup revocation verification failed: {err}"))
        })?;

    let actor_key = KeyId::parse(&cli.actor_key).map_err(|err| {
        CliError::CliArgs(format!("invalid --actor-key '{}': {err}", cli.actor_key))
    })?;

    let policy_map = load_cli_policy_map_file(&cli.policy_map)
        .and_then(|map| map.compile())
        .map_err(|err| match err {
            PolicyError::Io(msg) => {
                CliError::PolicyIo(format!("failed to load --policy-map: {msg}"))
            }
            other => CliError::PolicyInvalid(format!("failed to load --policy-map: {other}")),
        })?;

    let clock = RuntimeClock::from_optional_rfc3339(cli.now.as_deref()).map_err(|err| {
        CliError::CliArgs(format!(
            "invalid --now '{}': {err}",
            cli.now.as_deref().unwrap_or("")
        ))
    })?;

    let ledger = SqliteLedger::open(&cli.ledger).map_err(|err| {
        CliError::LedgerOpen(format!(
            "failed to open ledger '{}': {err}",
            cli.ledger.display()
        ))
    })?;

    let engine = GateEngine::new(verified_chain, actor_key, ledger, clock)
        .map(|engine| engine.with_revocations(verified_revocations))
        .map_err(|err| CliError::ChainInvalid(format!("failed to initialize GateEngine: {err}")))?;

    Ok(ExecProxy::new(engine, policy_map, OsCommandExecutor))
}

fn map_proxy_error(err: ProxyError) -> CliError {
    match err {
        ProxyError::Secret(secret_err) => CliError::SecretLoad(secret_err.to_string()),
        ProxyError::Exec(exec_err) => CliError::ExecFailed(exec_err.to_string()),
        other => CliError::RuntimeError(other.to_string()),
    }
}

fn format_denied_json(reason: &str, receipt_hash: &str) -> String {
    let mut out = String::from(r#"{"error":"handfest_denied","reason":"#);
    write_json_string(reason, &mut out);
    out.push_str(r#","receipt_hash":"#);
    write_json_string(receipt_hash, &mut out);
    out.push('}');
    out
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    if code == 0 {
        ExitCode::SUCCESS
    } else if let Ok(byte) = u8::try_from(code) {
        ExitCode::from(byte)
    } else {
        ExitCode::FAILURE
    }
}

fn map_envelope_load_error(err: PepError) -> CliError {
    match err {
        PepError::Io(io_err) => CliError::ChainIo(io_err.to_string()),
        other => CliError::ChainInvalid(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_core::exact_json::{parse_exact_json, ExactJson};

    #[test]
    fn denied_json_and_cli_errors_are_valid_single_line_json() {
        let denied = format_denied_json("quota \"exceeded\"\nline2", "sha256:abcd");
        assert!(!denied.contains('\n'));
        let parsed = parse_exact_json(&denied).expect("valid JSON");
        let obj = parsed.as_object().expect("JSON object");
        assert_eq!(obj.len(), 3);
        assert_eq!(
            obj.get("error"),
            Some(&ExactJson::Str("handfest_denied".to_string()))
        );
        assert_eq!(
            obj.get("reason"),
            Some(&ExactJson::Str("quota \"exceeded\"\nline2".to_string()))
        );
        assert_eq!(
            obj.get("receipt_hash"),
            Some(&ExactJson::Str("sha256:abcd".to_string()))
        );

        let err = CliError::SecretLoad("missing secret".to_string());
        assert_eq!(err.code(), "secret_load");
        assert_eq!(err.to_string(), "secret_load: missing secret");
        let err_json = parse_exact_json(&err.to_json_line()).expect("valid JSON");
        let err_obj = err_json.as_object().expect("object");
        assert_eq!(
            err_obj.get("error"),
            Some(&ExactJson::Str("exec_error".to_string()))
        );
        assert_eq!(
            err_obj.get("code"),
            Some(&ExactJson::Str("secret_load".to_string()))
        );
        assert_eq!(
            err_obj.get("message"),
            Some(&ExactJson::Str("missing secret".to_string()))
        );
    }

    #[test]
    fn exit_code_conversion_is_fail_closed_for_out_of_range_codes() {
        assert_eq!(exit_code_from_i32(0), ExitCode::SUCCESS);
        assert_eq!(exit_code_from_i32(42), ExitCode::from(42));
        assert_eq!(exit_code_from_i32(256), ExitCode::FAILURE);
        assert_eq!(exit_code_from_i32(-1), ExitCode::FAILURE);
    }

    #[test]
    fn cli_error_variants_map_proxy_error_and_runtime_clock_cover_all_paths() {
        use handfest_exec::{ExecError, SecretError};
        use handfest_ledger::LedgerError;

        let all_cli_errors = [
            (CliError::CliArgs("bad args".into()), "cli_args", "bad args"),
            (CliError::ChainIo("missing".into()), "chain_io", "missing"),
            (
                CliError::ChainInvalid("bad sig".into()),
                "chain_invalid",
                "bad sig",
            ),
            (
                CliError::PolicyIo("missing pol".into()),
                "policy_io",
                "missing pol",
            ),
            (
                CliError::PolicyInvalid("bad pol".into()),
                "policy_invalid",
                "bad pol",
            ),
            (
                CliError::LedgerOpen("locked".into()),
                "ledger_open",
                "locked",
            ),
            (CliError::SecretLoad("perm".into()), "secret_load", "perm"),
            (
                CliError::ExecFailed("enoent".into()),
                "exec_failed",
                "enoent",
            ),
            (
                CliError::RuntimeError("boom".into()),
                "runtime_error",
                "boom",
            ),
        ];
        for (err, expected_code, expected_msg) in all_cli_errors {
            assert_eq!(err.code(), expected_code);
            assert_eq!(err.message(), expected_msg);
            assert_eq!(err.to_string(), format!("{expected_code}: {expected_msg}"));
            let parsed = parse_exact_json(&err.to_json_line()).expect("valid JSON");
            let obj = parsed.as_object().expect("JSON object");
            assert_eq!(
                obj.get("error"),
                Some(&ExactJson::Str("exec_error".to_string()))
            );
            assert_eq!(
                obj.get("code"),
                Some(&ExactJson::Str(expected_code.to_string()))
            );
            assert_eq!(
                obj.get("message"),
                Some(&ExactJson::Str(expected_msg.to_string()))
            );
        }

        assert_eq!(
            map_proxy_error(ProxyError::Secret(SecretError::MissingEnvVar("TOK".into()))).code(),
            "secret_load"
        );
        assert_eq!(
            map_proxy_error(ProxyError::Exec(ExecError::RelativeExecutable(
                PathBuf::from("rel")
            )))
            .code(),
            "exec_failed"
        );
        assert_eq!(
            map_proxy_error(ProxyError::Pep(PepError::InvalidChain("bad chain".into()))).code(),
            "runtime_error"
        );
        assert_eq!(
            map_proxy_error(ProxyError::Ledger(LedgerError::Storage("io".into()))).code(),
            "runtime_error"
        );
        assert_eq!(
            map_proxy_error(ProxyError::EnvVarNotUnicode("BAD".into())).code(),
            "runtime_error"
        );

        assert_eq!(
            map_envelope_load_error(PepError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "missing"
            )))
            .code(),
            "chain_io"
        );
        assert_eq!(
            map_envelope_load_error(PepError::InvalidChain("bad json".into())).code(),
            "chain_invalid"
        );

        use handfest_pep::{Clock, FixedClock, SystemClock};
        assert!(RuntimeClock::System(SystemClock).now_unix() > 1_700_000_000);
        assert_eq!(
            RuntimeClock::Fixed(FixedClock::new(12345)).now_unix(),
            12345
        );
    }
}
