//! `handfest request` subcommand: submits a draft mandate to an out-of-band `handfest-approver`
//! daemon over a Unix domain socket and writes the independently verified `SignedMandate` JSON.

#[cfg(unix)]
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
#[cfg(unix)]
use handfest_anchors::AnchorRegistry;
#[cfg(unix)]
use handfest_approver::client::{request_and_verify_signature, DEFAULT_CLIENT_TIMEOUT_SECS};
#[cfg(unix)]
use handfest_approver::protocol::SignRequest;

#[cfg(unix)]
use crate::parse_timestamp_arg;

#[cfg(not(unix))]
const DEFAULT_CLIENT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Args)]
pub(crate) struct RequestCliArgs {
    /// Path to the out-of-band `handfest-approver` Unix domain socket.
    #[arg(long)]
    pub(crate) socket: PathBuf,
    /// Path to the draft HANDFEST v1 mandate text file.
    #[arg(long)]
    pub(crate) mandate: PathBuf,
    /// Anchor validity start timestamp (RFC 3339 UTC or Unix seconds).
    #[arg(long)]
    pub(crate) valid_from: String,
    /// Anchor validity end timestamp (RFC 3339 UTC or Unix seconds).
    #[arg(long)]
    pub(crate) valid_until: String,
    /// Optional trust anchor identifier override requested from the approver daemon.
    #[arg(long)]
    pub(crate) anchor_id: Option<String>,
    /// Maximum time in seconds to wait for human approval from the daemon.
    #[arg(long, default_value_t = DEFAULT_CLIENT_TIMEOUT_SECS)]
    pub(crate) timeout_secs: u64,
    /// Optional path to write the verified SignedMandate JSON (prints JSON to stdout if omitted).
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[cfg(not(unix))]
pub(crate) fn run_request_cli(_args: RequestCliArgs) -> Result<ExitCode, String> {
    Err("handfest request requires a Unix platform with Unix domain socket support".to_string())
}

#[cfg(unix)]
pub(crate) fn run_request_cli(args: RequestCliArgs) -> Result<ExitCode, String> {
    let timeout = handfest_approver::validate_timeout_secs(args.timeout_secs)?;
    let mandate_text = fs::read_to_string(&args.mandate)
        .map_err(|err| format!("failed to read '{}': {err}", args.mandate.display()))?;
    let valid_from = parse_timestamp_arg("valid-from", &args.valid_from)?;
    let valid_until = parse_timestamp_arg("valid-until", &args.valid_until)?;

    let request = SignRequest {
        mandate_text,
        valid_from,
        valid_until,
        anchor_id: args.anchor_id,
    };

    let registry = AnchorRegistry::default_registry();
    let approved = request_and_verify_signature(&args.socket, &request, &registry, Some(timeout))
        .map_err(|err| err.to_string())?;

    let json_text = serde_json::to_string_pretty(&approved.signed_mandate)
        .map_err(|err| format!("serialize error: {err}"))?;

    if let Some(path) = args.out.as_deref() {
        fs::write(path, format!("{json_text}\n"))
            .map_err(|err| format!("failed to write '{}': {err}", path.display()))?;
        println!("{}", approved.mandate_id);
    } else {
        println!("{json_text}");
    }
    Ok(ExitCode::SUCCESS)
}
