//! Transport-agnostic Policy Enforcement Point gate engine.

use std::fmt;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    check_chain_revocations, verify_chain_runtime, ActionRequest, DecisionReceipt,
    RevocationSnapshot, VerifiedFacts, VerifiedMandate,
};
use handfest_core::Verdict;
use handfest_ledger::{ReceiptLedger, SqliteLedger};

use crate::chain::validate_verified_chain;
use crate::clock::Clock;
use crate::error::PepError;

/// Outcome of an atomic [`GateEngine::authorize`] evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Request permitted; quotas incremented and hash-chained receipt persisted.
    Permit { receipt: DecisionReceipt },
    /// Request denied; quotas untouched and hash-chained denial receipt persisted.
    Deny {
        reason: String,
        receipt: DecisionReceipt,
    },
}

/// Outcome of recording a pre-gate (mapping / validation) denial receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreGateDenial {
    /// Effective denial reason (chain/revocation failure takes precedence over mapping error).
    pub reason: String,
    /// Hash-chained denial receipt persisted to the ledger.
    pub receipt: DecisionReceipt,
}

/// Transport-agnostic fail-closed authorization engine over a verified mandate chain,
/// tamper-evident [`ReceiptLedger`], and [`Clock`].
pub struct GateEngine<C: Clock, L: ReceiptLedger = SqliteLedger> {
    verified_chain: Vec<VerifiedMandate>,
    chain_ids: Vec<MandateId>,
    actor_key: KeyId,
    ledger: L,
    clock: C,
    extra_revocations: RevocationSnapshot,
}

impl<C: Clock, L: ReceiptLedger> fmt::Debug for GateEngine<C, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateEngine")
            .field("chain_len", &self.verified_chain.len())
            .field("actor_key", &self.actor_key)
            .finish_non_exhaustive()
    }
}

impl<C: Clock, L: ReceiptLedger> GateEngine<C, L> {
    /// Constructs a validated [`GateEngine`] over a verified mandate chain and [`ReceiptLedger`].
    pub fn new(
        verified_chain: Vec<VerifiedMandate>,
        actor_key: KeyId,
        ledger: L,
        clock: C,
    ) -> Result<Self, PepError> {
        let chain_ids = validate_verified_chain(&verified_chain)?;
        actor_key
            .validate()
            .map_err(|err| PepError::InvalidChain(format!("invalid actor_key: {err}")))?;
        Ok(Self {
            verified_chain,
            chain_ids,
            actor_key,
            ledger,
            clock,
            extra_revocations: RevocationSnapshot::new(),
        })
    }

    /// Attaches static verified revocations enforced alongside revocations persisted in `ledger`.
    #[must_use]
    pub fn with_revocations(mut self, revocations: RevocationSnapshot) -> Self {
        self.extra_revocations = revocations;
        self
    }

    /// Returns the current UTC Unix timestamp from the configured [`Clock`].
    #[must_use]
    pub fn now_unix(&self) -> i64 {
        self.clock.now_unix()
    }

    /// Borrows the verified mandate chain (root first, leaf last).
    #[must_use]
    pub fn verified_chain(&self) -> &[VerifiedMandate] {
        &self.verified_chain
    }

    /// Borrows the ordered [`MandateId`] digests for the verified chain.
    #[must_use]
    pub fn chain_ids(&self) -> &[MandateId] {
        &self.chain_ids
    }

    /// Borrows the concrete acting [`KeyId`].
    #[must_use]
    pub const fn actor_key(&self) -> &KeyId {
        &self.actor_key
    }

    /// Borrows the underlying [`ReceiptLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Mutably borrows the underlying [`ReceiptLedger`].
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut L {
        &mut self.ledger
    }

    /// Consumes the engine and returns its underlying [`ReceiptLedger`].
    #[must_use]
    pub fn into_ledger(self) -> L {
        self.ledger
    }

    /// Atomically evaluates `request` and `facts` at `self.now_unix()`, persists a hash-chained
    /// receipt, and increments chain quotas on [`GateDecision::Permit`].
    pub fn authorize(
        &mut self,
        request: &ActionRequest,
        facts: &VerifiedFacts,
    ) -> Result<GateDecision, PepError> {
        let now = self.clock.now_unix();
        self.authorize_at(request, facts, now)
    }

    /// Atomically evaluates `request` and `facts` at an explicit UTC Unix timestamp `now`.
    ///
    /// If `request.actor_key != self.actor_key`, records a pre-gate denial attributed to
    /// `self.actor_key` without incrementing any quotas.
    pub fn authorize_at(
        &mut self,
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<GateDecision, PepError> {
        if request.actor_key != self.actor_key {
            let denial = self.record_pre_gate_denial(
                request,
                format!(
                    "request actor_key '{}' does not match engine actor_key '{}'",
                    request.actor_key, self.actor_key
                ),
                now,
            )?;
            return Ok(GateDecision::Deny {
                reason: denial.reason,
                receipt: denial.receipt,
            });
        }
        let (verdict, receipt) = self.ledger.evaluate_and_record_with_revocations(
            &self.verified_chain,
            request,
            facts,
            &self.extra_revocations,
            now,
        )?;
        Ok(match verdict {
            Verdict::Permit => GateDecision::Permit { receipt },
            Verdict::Deny { reason } => GateDecision::Deny { reason, receipt },
        })
    }

    /// Checks combined persisted + static revocations for the mandate chain at `evaluated_at`.
    ///
    /// Returns `Err(PepError::Ledger(_))` if loading persisted revocations fails (fail-closed on
    /// tamper), `Ok(Err(reason))` if a mandate in the chain is revoked, or `Ok(Ok(()))` if clear.
    pub fn check_revocation_status(
        &self,
        evaluated_at: i64,
    ) -> Result<Result<(), String>, PepError> {
        let mut combined = self.ledger.load_revocations()?;
        combined.extend_from(&self.extra_revocations);
        Ok(
            check_chain_revocations(&self.verified_chain, &combined, evaluated_at)
                .map_err(|deny| deny.to_string()),
        )
    }

    /// Returns `Ok(true)` iff the chain is active for `actor_key` at `evaluated_at` and not
    /// revoked, `Ok(false)` if expired/inactive/revoked, or `Err(PepError::Ledger(_))` on ledger
    /// integrity failure.
    pub fn is_chain_active(&self, evaluated_at: i64) -> Result<bool, PepError> {
        let rev_status = self.check_revocation_status(evaluated_at)?;
        Ok(
            verify_chain_runtime(&self.verified_chain, &self.actor_key, evaluated_at).is_ok()
                && rev_status.is_ok(),
        )
    }

    /// Records a pre-gate denial receipt (e.g. unmapped tool/route or invalid arguments) without
    /// modifying quota counters.
    ///
    /// Preserves strict precedence: runtime chain failure (e.g. expired mandate) > active
    /// revocation > `mapping_reason`.
    pub fn record_pre_gate_denial(
        &mut self,
        denial_request: &ActionRequest,
        mapping_reason: String,
        now: i64,
    ) -> Result<PreGateDenial, PepError> {
        let (reason, receipt) = self.ledger.record_denial_with_revocations(
            &self.verified_chain,
            &self.actor_key,
            denial_request,
            &self.extra_revocations,
            now,
            mapping_reason,
        )?;
        Ok(PreGateDenial { reason, receipt })
    }
}
