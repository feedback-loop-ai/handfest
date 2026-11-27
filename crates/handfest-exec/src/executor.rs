//! Fail-closed command execution trait, OS process executor (no shell), and [`ExecProxy`].

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;

use handfest_core::gate::{ActionRequest, DecisionReceipt};
use handfest_ledger::{LedgerError, ReceiptLedger, SqliteLedger};
use handfest_pep::{Clock, GateDecision, GateEngine, PepError, SecretError};

use crate::argv::{denial_resource_id, parse_and_map_argv};
use crate::policy::{CommandPolicy, CompiledCliPolicyMap};

/// Fully resolved, validated child-process execution specification.
///
/// [`fmt::Debug`] redacts all environment values so injected secrets cannot leak into logs or
/// panic messages.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

impl fmt::Debug for ExecSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_env: BTreeMap<&str, &str> = self
            .env
            .keys()
            .map(|k| (k.as_str(), "[REDACTED]"))
            .collect();
        f.debug_struct("ExecSpec")
            .field("executable", &self.executable)
            .field("args", &self.args)
            .field("env", &redacted_env)
            .finish()
    }
}

/// Captured output from executing a permitted command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Errors returned by a [`CommandExecutor`] implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    RelativeExecutable(PathBuf),
    SpawnFailed { executable: PathBuf, detail: String },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeExecutable(path) => write!(
                f,
                "refusing to execute relative executable path '{}'",
                path.display()
            ),
            Self::SpawnFailed { executable, detail } => {
                write!(f, "failed to execute '{}': {detail}", executable.display())
            }
        }
    }
}

impl std::error::Error for ExecError {}

/// Execution seam allowing deterministic unit/integration tests without spawning OS processes.
pub trait CommandExecutor {
    /// Executes the command described by `spec` directly (never via a shell).
    fn exec(&self, spec: &ExecSpec) -> Result<ExecOutput, ExecError>;
}

/// Production OS process executor invoking `std::process::Command` directly with `.env_clear()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsCommandExecutor;

impl CommandExecutor for OsCommandExecutor {
    fn exec(&self, spec: &ExecSpec) -> Result<ExecOutput, ExecError> {
        if !spec.executable.is_absolute()
            || spec
                .executable
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ExecError::RelativeExecutable(spec.executable.clone()));
        }
        let output = Command::new(&spec.executable)
            .env_clear()
            .envs(&spec.env)
            .args(&spec.args)
            .output()
            .map_err(|err| ExecError::SpawnFailed {
                executable: spec.executable.clone(),
                detail: err.to_string(),
            })?;

        let exit_code = status_exit_code(&output.status);
        Ok(ExecOutput {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn status_exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

/// Outcome of a single [`ExecProxy::execute`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecOutcome {
    /// Request permitted, secrets injected, and child process executed.
    Permitted {
        receipt: DecisionReceipt,
        output: ExecOutput,
    },
    /// Request denied (pre-gate mapping refusal or mandate/quota/revocation denial).
    /// Neither secrets nor the target executable were touched.
    Denied {
        reason: String,
        receipt: DecisionReceipt,
    },
}

/// Runtime errors returned by [`ExecProxy::execute`].
#[derive(Debug)]
pub enum ProxyError {
    Pep(PepError),
    Ledger(LedgerError),
    Secret(SecretError),
    EnvVarNotUnicode(String),
    Exec(ExecError),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pep(err) => write!(f, "PEP error: {err}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::Secret(err) => write!(f, "credential error: {err}"),
            Self::EnvVarNotUnicode(var) => {
                write!(f, "pass_env variable '{var}' contains non-UTF-8 data")
            }
            Self::Exec(err) => write!(f, "execution error: {err}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pep(err) => Some(err),
            Self::Ledger(err) => Some(err),
            Self::Secret(err) => Some(err),
            Self::Exec(err) => Some(err),
            Self::EnvVarNotUnicode(_) => None,
        }
    }
}

impl From<PepError> for ProxyError {
    fn from(err: PepError) -> Self {
        match err {
            PepError::Ledger(ledger_err) => Self::Ledger(ledger_err),
            PepError::Secret(secret_err) => Self::Secret(secret_err),
            other => Self::Pep(other),
        }
    }
}

/// Fail-closed CLI Policy Enforcement Point wrapping [`GateEngine`], [`CompiledCliPolicyMap`],
/// and a pluggable [`CommandExecutor`].
pub struct ExecProxy<
    C: Clock,
    L: ReceiptLedger = SqliteLedger,
    E: CommandExecutor = OsCommandExecutor,
> {
    engine: GateEngine<C, L>,
    policy_map: CompiledCliPolicyMap,
    executor: E,
}

impl<C: Clock, L: ReceiptLedger, E: CommandExecutor> fmt::Debug for ExecProxy<C, L, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecProxy")
            .field("chain_len", &self.engine.verified_chain().len())
            .field("actor_key", self.engine.actor_key())
            .field(
                "mapped_commands",
                &self.policy_map.policy_map().commands.len(),
            )
            .finish_non_exhaustive()
    }
}

impl<C: Clock, L: ReceiptLedger, E: CommandExecutor> ExecProxy<C, L, E> {
    /// Creates an [`ExecProxy`] from a validated [`GateEngine`], compiled policy map, and executor.
    #[must_use]
    pub const fn new(
        engine: GateEngine<C, L>,
        policy_map: CompiledCliPolicyMap,
        executor: E,
    ) -> Self {
        Self {
            engine,
            policy_map,
            executor,
        }
    }

    /// Borrows the underlying [`GateEngine`].
    #[must_use]
    pub const fn engine(&self) -> &GateEngine<C, L> {
        &self.engine
    }

    /// Borrows the underlying [`ReceiptLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &L {
        self.engine.ledger()
    }

    /// Consumes the proxy and returns its underlying [`ReceiptLedger`].
    #[must_use]
    pub fn into_ledger(self) -> L {
        self.engine.into_ledger()
    }

    /// Borrows the configured [`CommandExecutor`].
    #[must_use]
    pub const fn executor(&self) -> &E {
        &self.executor
    }

    /// Maps `command_name` + `raw_args`, evaluates the mandate chain atomically, and on `Permit`
    /// loads `env_secrets` and invokes `E::exec`.
    ///
    /// On mapping failure or gate `Deny`, records a tamper-evident denial receipt and NEVER loads
    /// secrets or invokes `E::exec`.
    pub fn execute(
        &mut self,
        command_name: &str,
        raw_args: &[String],
    ) -> Result<ExecOutcome, ProxyError> {
        let now = self.engine.now_unix();
        let mapped = match parse_and_map_argv(
            &self.policy_map,
            self.engine.actor_key(),
            command_name,
            raw_args,
        ) {
            Ok(mapped) => mapped,
            Err(argv_err) => {
                let denial_req = build_mapping_denial_request(
                    self.engine.actor_key(),
                    &self.policy_map,
                    command_name,
                    raw_args,
                );
                let denial =
                    self.engine
                        .record_pre_gate_denial(&denial_req, argv_err.to_string(), now)?;
                return Ok(ExecOutcome::Denied {
                    reason: denial.reason,
                    receipt: denial.receipt,
                });
            }
        };

        let decision = self
            .engine
            .authorize_at(&mapped.request, &mapped.facts, now)?;
        let receipt = match decision {
            GateDecision::Permit { receipt } => receipt,
            GateDecision::Deny { reason, receipt } => {
                return Ok(ExecOutcome::Denied { reason, receipt });
            }
        };

        // Guaranteed present because `parse_and_map_argv` succeeded for `command_name`.
        let policy = self
            .policy_map
            .get(command_name)
            .expect("mapped command must exist in compiled policy map");
        let spec = build_exec_spec(policy, mapped.validated_argv)?;
        let output = self.executor.exec(&spec).map_err(ProxyError::Exec)?;
        Ok(ExecOutcome::Permitted { receipt, output })
    }
}

fn build_mapping_denial_request(
    actor_key: &handfest_core::ast::KeyId,
    policy_map: &CompiledCliPolicyMap,
    command_name: &str,
    raw_args: &[String],
) -> ActionRequest {
    match policy_map.get(command_name) {
        Some(policy) => ActionRequest {
            actor_key: actor_key.clone(),
            action: policy.action.clone(),
            resource_kind: policy.resource_kind.clone(),
            resource_id: denial_resource_id(policy, raw_args),
        },
        None => ActionRequest {
            actor_key: actor_key.clone(),
            action: format!("exec.unmapped:{command_name}"),
            resource_kind: "cli_command".to_string(),
            resource_id: command_name.to_string(),
        },
    }
}

fn build_exec_spec(
    policy: &CommandPolicy,
    validated_argv: Vec<String>,
) -> Result<ExecSpec, ProxyError> {
    let mut env_map = BTreeMap::new();
    for var in &policy.pass_env {
        match env::var(var) {
            Ok(val) => {
                env_map.insert(var.clone(), val);
            }
            Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ProxyError::EnvVarNotUnicode(var.clone()));
            }
        }
    }
    for (env_name, source) in &policy.env_secrets {
        let secret = source.load().map_err(ProxyError::Secret)?;
        env_map.insert(env_name.clone(), secret.as_str().to_string());
    }

    let mut args = Vec::with_capacity(policy.fixed_args.len() + validated_argv.len());
    args.extend(policy.fixed_args.iter().cloned());
    args.extend(validated_argv);

    Ok(ExecSpec {
        executable: policy.executable.clone(),
        args,
        env: env_map,
    })
}
