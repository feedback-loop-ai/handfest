//! Opt-in external checkpoint witness CLI plumbing (`--witness none|ots`, `--verify-witness`,
//! and `--expected-checkpoint`).

use std::path::Path;
use std::process::ExitCode;

use clap::ValueEnum;
use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    ActionRequest, DecisionReceipt, RevocationSnapshot, VerifiedFacts, VerifiedMandate,
    VerifiedRevocation,
};
use handfest_core::revocation::RevocationId;
use handfest_core::Verdict;
use handfest_ledger::{
    canonical_checkpoint_sidecar_path, verify_audit_snapshot_with_witness, AuditSnapshot,
    LedgerError, SqliteLedger, WitnessError, WitnessRegistry,
};
use serde_json::json;

#[cfg(feature = "witness-ots")]
use handfest_ledger::{AnchoredLedger, OtsWitness, ReceiptLedger, WitnessPolicy};

use crate::revoke::verify_stored_revocations_signatures;

/// Runtime witness selection for CLI write commands (`--witness none` default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub(crate) enum WitnessMode {
    /// Disabled (default): zero external witness calls, zero sidecar I/O, zero overhead.
    #[default]
    None,
    /// OpenTimestamps (`ots`) witness (requires building with `--features witness-ots`).
    Ots,
}

/// Structured witness audit error emitted on `stderr` as JSON when `handfest audit
/// --verify-witness` fails so callers can distinguish missing sidecars, rollback/digest
/// mismatches, and proof verification failures deterministically without scraping prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessAuditError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl WitnessAuditError {
    pub(crate) fn to_json_value(&self) -> serde_json::Value {
        json!({
            "error": "witness_verification_failed",
            "code": self.code,
            "message": self.message,
        })
    }

    pub(crate) fn emit_stderr(&self) {
        eprintln!("{}", self.to_json_value());
    }
}

pub(crate) fn classify_witness_audit_error(err: &LedgerError) -> &'static str {
    match err {
        LedgerError::NotFound(_) => "missing_sidecar",
        LedgerError::Integrity(_) => "integrity_or_rollback_mismatch",
        LedgerError::Witness(w_err) => classify_witness_error(w_err),
        LedgerError::Storage(_) | LedgerError::Json(_) | LedgerError::QuotaAccounting(_) => {
            "storage_error"
        }
    }
}

pub(crate) fn classify_ledger_open_audit_error(err: &LedgerError) -> &'static str {
    match err {
        LedgerError::NotFound(_) => "missing_ledger",
        LedgerError::Integrity(_) => "invalid_or_corrupt_ledger",
        LedgerError::Witness(w_err) => classify_witness_error(w_err),
        LedgerError::Storage(_) | LedgerError::Json(_) | LedgerError::QuotaAccounting(_) => {
            "storage_error"
        }
    }
}

fn fail_audit(
    verify_witness: bool,
    code: &'static str,
    message: String,
) -> Result<Result<serde_json::Value, WitnessAuditError>, String> {
    if verify_witness {
        Ok(Err(WitnessAuditError { code, message }))
    } else {
        Err(message)
    }
}

fn classify_witness_error(err: &WitnessError) -> &'static str {
    match err {
        WitnessError::DigestMismatch { .. } => "digest_mismatch",
        WitnessError::UnsupportedWitnessKind(_) => "unsupported_witness_kind",
        WitnessError::VerificationFailed(_)
        | WitnessError::CommandFailed { .. }
        | WitnessError::CommandIo { .. }
        | WitnessError::Backend(_)
        | WitnessError::TempFileIo(_) => "proof_verification_failed",
        WitnessError::InvalidCheckpoint(_)
        | WitnessError::InvalidProof(_)
        | WitnessError::InvalidConfig(_)
        | WitnessError::KindMismatch { .. } => "invalid_checkpoint_or_proof",
    }
}

/// Validates that the requested [`WitnessMode`] is compiled into this binary before signing,
/// opening/creating SQLite ledgers, or writing `--out` files.
pub(crate) fn validate_witness_mode(mode: WitnessMode) -> Result<(), String> {
    match mode {
        WitnessMode::None => Ok(()),
        WitnessMode::Ots => {
            #[cfg(feature = "witness-ots")]
            {
                Ok(())
            }
            #[cfg(not(feature = "witness-ots"))]
            {
                Err(
                    "--witness ots requires building handfest-cli with '--features witness-ots'"
                        .to_string(),
                )
            }
        }
    }
}

/// Bundled evaluation inputs for [`evaluate_with_witness`].
pub(crate) struct WitnessedEvalContext<'a> {
    pub(crate) ledger_path: &'a Path,
    pub(crate) witness_mode: WitnessMode,
    pub(crate) verified: &'a [VerifiedMandate],
    pub(crate) request: &'a ActionRequest,
    pub(crate) facts: &'a VerifiedFacts,
    pub(crate) extra_revocations: &'a RevocationSnapshot,
    pub(crate) now: i64,
}

/// Evaluates `ctx.request` against `ctx.verified` and records the receipt, optionally anchoring
/// `Permit` checkpoints via `ctx.witness_mode`.
pub(crate) fn evaluate_with_witness(
    mut ledger: SqliteLedger,
    ctx: &WitnessedEvalContext<'_>,
) -> Result<(Verdict, DecisionReceipt), String> {
    match ctx.witness_mode {
        WitnessMode::None => ledger
            .evaluate_and_record_with_revocations(
                ctx.verified,
                ctx.request,
                ctx.facts,
                ctx.extra_revocations,
                ctx.now,
            )
            .map_err(|err| format!("ledger evaluation failed: {err}")),
        WitnessMode::Ots => {
            #[cfg(feature = "witness-ots")]
            {
                let sidecar = canonical_checkpoint_sidecar_path(ctx.ledger_path)
                    .map_err(|err| format!("failed to resolve checkpoint sidecar path: {err}"))?;
                let mut anchored = AnchoredLedger::with_checkpoint_file(
                    ledger,
                    OtsWitness::new(),
                    WitnessPolicy::SyncStrict,
                    sidecar,
                )
                .map_err(|err| format!("failed to initialize OTS witness ledger: {err}"))?;
                anchored
                    .evaluate_and_record_with_revocations(
                        ctx.verified,
                        ctx.request,
                        ctx.facts,
                        ctx.extra_revocations,
                        ctx.now,
                    )
                    .map_err(|err| format!("ledger evaluation failed: {err}"))
            }
            #[cfg(not(feature = "witness-ots"))]
            {
                let _ = (&mut ledger, ctx.ledger_path);
                validate_witness_mode(WitnessMode::Ots)?;
                unreachable!("validate_witness_mode(Ots) always fails without witness-ots feature")
            }
        }
    }
}

/// Records `verified` revocation in `ledger`, optionally anchoring the updated checkpoint via the
/// selected [`WitnessMode`].
pub(crate) fn record_revocation_with_witness(
    mut ledger: SqliteLedger,
    ledger_path: &Path,
    witness_mode: WitnessMode,
    verified: &VerifiedRevocation,
    signature_hex: &str,
) -> Result<RevocationId, String> {
    match witness_mode {
        WitnessMode::None => ledger
            .record_revocation(verified, signature_hex)
            .map_err(|err| format!("failed to record revocation in ledger: {err}")),
        WitnessMode::Ots => {
            #[cfg(feature = "witness-ots")]
            {
                let sidecar = canonical_checkpoint_sidecar_path(ledger_path)
                    .map_err(|err| format!("failed to resolve checkpoint sidecar path: {err}"))?;
                let mut anchored = AnchoredLedger::with_checkpoint_file(
                    ledger,
                    OtsWitness::new(),
                    WitnessPolicy::SyncStrict,
                    sidecar,
                )
                .map_err(|err| format!("failed to initialize OTS witness ledger: {err}"))?;
                anchored
                    .record_revocation(verified, signature_hex)
                    .map_err(|err| format!("failed to record revocation in ledger: {err}"))
            }
            #[cfg(not(feature = "witness-ots"))]
            {
                let _ = (&mut ledger, ledger_path, verified, signature_hex);
                validate_witness_mode(WitnessMode::Ots)?;
                unreachable!("validate_witness_mode(Ots) always fails without witness-ots feature")
            }
        }
    }
}

/// Atomically captures a single consistent [`AuditSnapshot`] from `ledger` and verifies all
/// persisted witness checkpoints in `<canonical_ledger_path>.checkpoints.jsonl` against that
/// exact snapshot, `registry`, and optional operator-pinned `expected_checkpoint_head`.
pub(crate) fn audit_snapshot_with_witness(
    ledger: &SqliteLedger,
    ledger_path: &Path,
    actor_key: Option<&KeyId>,
    registry: &WitnessRegistry,
    expected_checkpoint_head: Option<&MandateId>,
) -> Result<(AuditSnapshot, usize), WitnessAuditError> {
    let sidecar =
        canonical_checkpoint_sidecar_path(ledger_path).map_err(|err| WitnessAuditError {
            code: classify_witness_audit_error(&err),
            message: format!("audit witness sidecar path resolution failed: {err}"),
        })?;
    verify_audit_snapshot_with_witness(
        ledger,
        actor_key,
        &sidecar,
        registry,
        true,
        expected_checkpoint_head,
    )
    .map_err(|err| WitnessAuditError {
        code: classify_witness_audit_error(&err),
        message: format!("audit witness checkpoint verification failed: {err}"),
    })
}

pub(crate) fn cmd_audit(
    ledger_path: &Path,
    actor_key_raw: Option<&str>,
    verify_witness: bool,
    expected_checkpoint_raw: Option<&str>,
) -> Result<ExitCode, String> {
    let registry = WitnessRegistry::with_defaults();
    cmd_audit_with_registry(
        ledger_path,
        actor_key_raw,
        verify_witness,
        expected_checkpoint_raw,
        &registry,
    )
}

pub(crate) fn execute_audit_with_registry(
    ledger_path: &Path,
    actor_key_raw: Option<&str>,
    verify_witness: bool,
    expected_checkpoint_raw: Option<&str>,
    registry: &WitnessRegistry,
) -> Result<Result<serde_json::Value, WitnessAuditError>, String> {
    if expected_checkpoint_raw.is_some() && !verify_witness {
        return Err("--expected-checkpoint requires --verify-witness".to_string());
    }
    let actor_key = match actor_key_raw {
        Some(raw) => match KeyId::parse(raw) {
            Ok(key) => Some(key),
            Err(err) => {
                return fail_audit(
                    verify_witness,
                    "invalid_actor_key",
                    format!("invalid --actor-key '{raw}': {err}"),
                );
            }
        },
        None => None,
    };
    let expected_checkpoint = match expected_checkpoint_raw {
        Some(raw) => match MandateId::parse(raw) {
            Ok(id) => Some(id),
            Err(err) => {
                return fail_audit(
                    verify_witness,
                    "invalid_expected_checkpoint",
                    format!("invalid --expected-checkpoint '{raw}': {err}"),
                );
            }
        },
        None => None,
    };

    let ledger = match SqliteLedger::open_read_only(ledger_path) {
        Ok(ledger) => ledger,
        Err(err) => {
            return fail_audit(
                verify_witness,
                classify_ledger_open_audit_error(&err),
                format!("failed to open ledger '{}': {err}", ledger_path.display()),
            );
        }
    };
    let (snapshot, verified_checkpoints) = if verify_witness {
        match audit_snapshot_with_witness(
            &ledger,
            ledger_path,
            actor_key.as_ref(),
            registry,
            expected_checkpoint.as_ref(),
        ) {
            Ok((snap, checkpoints)) => (snap, Some(checkpoints)),
            Err(err) => return Ok(Err(err)),
        }
    } else {
        let snap = ledger
            .audit_full_snapshot(actor_key.as_ref(), false)
            .map_err(|err| format!("audit integrity check failed: {err}"))?;
        (snap, None)
    };
    if let Err(err) = verify_stored_revocations_signatures(&snapshot.stored_revocations) {
        return fail_audit(
            verify_witness,
            "invalid_revocation_signature",
            format!("audit revocation signature check failed: {err}"),
        );
    }
    let verified_receipts = snapshot.verified_receipts;
    let output = match (snapshot.track_record, verified_checkpoints) {
        (Some(record), Some(checkpoints)) => json!({
            "status": "ok",
            "verified_receipts": verified_receipts,
            "verified_checkpoints": checkpoints,
            "track_record": record,
        }),
        (Some(record), None) => json!({
            "status": "ok",
            "verified_receipts": verified_receipts,
            "track_record": record,
        }),
        (None, Some(checkpoints)) => json!({
            "status": "ok",
            "verified_receipts": verified_receipts,
            "verified_checkpoints": checkpoints,
        }),
        (None, None) => json!({
            "status": "ok",
            "verified_receipts": verified_receipts,
        }),
    };
    Ok(Ok(output))
}

pub(crate) fn cmd_audit_with_registry(
    ledger_path: &Path,
    actor_key_raw: Option<&str>,
    verify_witness: bool,
    expected_checkpoint_raw: Option<&str>,
    registry: &WitnessRegistry,
) -> Result<ExitCode, String> {
    match execute_audit_with_registry(
        ledger_path,
        actor_key_raw,
        verify_witness,
        expected_checkpoint_raw,
        registry,
    )? {
        Ok(output) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            err.emit_stderr();
            Ok(ExitCode::FAILURE)
        }
    }
}
