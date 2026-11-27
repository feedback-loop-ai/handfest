//! Tamper-evident hash-chained SQLite persistence and integrity verification for revocations.

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{VerifiedAnchorProof, VerifiedRevocation};
use handfest_core::revocation::{
    parse_canonical_revocation, render_canonical_revocation, validate_verified_revocation,
    RevocationId, RevocationSnapshot,
};
use handfest_core::{ActorKind, AssuranceLevel};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::audit::verify_sqlite_sequence_hwm;
use crate::codec::{col_i64, col_opt_text, col_text, parse_optional_mandate_id};
use crate::LedgerError;

const REVOCATION_ENTRY_HASH_PREFIX: &[u8] = b"HANDFEST-REVOCATION-ENTRY-v1\0";

/// Complete verified revocation envelope record persisted in a [`crate::ReceiptLedger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRevocation {
    pub revocation_id: RevocationId,
    pub verified: VerifiedRevocation,
    pub signature_hex: String,
}

struct EntryHashInput<'a> {
    prev_entry_hash: Option<MandateId>,
    revocation_id: RevocationId,
    canonical_words: &'a str,
    anchor_id: &'a str,
    assurance: &'a str,
    actor_kind: &'a str,
    signer_key: &'a str,
    valid_from: i64,
    valid_until: i64,
    signature_hex: &'a str,
}

fn compute_revocation_entry_hash(input: &EntryHashInput<'_>) -> MandateId {
    let mut buf = Vec::with_capacity(
        REVOCATION_ENTRY_HASH_PREFIX.len()
            + 64
            + input.canonical_words.len()
            + input.anchor_id.len()
            + input.assurance.len()
            + input.actor_kind.len()
            + input.signer_key.len()
            + input.signature_hex.len(),
    );
    buf.extend_from_slice(REVOCATION_ENTRY_HASH_PREFIX);
    match input.prev_entry_hash {
        None => buf.push(0u8),
        Some(prev) => {
            buf.push(1u8);
            buf.extend_from_slice(prev.as_bytes());
        }
    }
    buf.extend_from_slice(input.revocation_id.as_bytes());
    push_len_prefixed_str(&mut buf, input.canonical_words);
    push_len_prefixed_str(&mut buf, input.anchor_id);
    push_len_prefixed_str(&mut buf, input.assurance);
    push_len_prefixed_str(&mut buf, input.actor_kind);
    push_len_prefixed_str(&mut buf, input.signer_key);
    buf.extend_from_slice(&input.valid_from.to_be_bytes());
    buf.extend_from_slice(&input.valid_until.to_be_bytes());
    push_len_prefixed_str(&mut buf, input.signature_hex);
    MandateId::sha256(&buf)
}

fn push_len_prefixed_str(buf: &mut Vec<u8>, value: &str) {
    let len = u64::try_from(value.len()).expect("string byte length fits in u64");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn format_actor_kind(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Org => "org",
        ActorKind::Agent => "agent",
        ActorKind::Service => "service",
    }
}

fn parse_actor_kind(raw: &str) -> Result<ActorKind, LedgerError> {
    match raw {
        "human" => Ok(ActorKind::Human),
        "org" => Ok(ActorKind::Org),
        "agent" => Ok(ActorKind::Agent),
        "service" => Ok(ActorKind::Service),
        other => Err(LedgerError::Integrity(format!(
            "unknown revocation actor_kind '{other}'"
        ))),
    }
}

fn format_assurance(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::LocalKey => "local_key",
        AssuranceLevel::CryptoWallet => "crypto_wallet",
        AssuranceLevel::Passkey => "passkey",
        AssuranceLevel::SubstantialEidas => "substantial_eidas",
        AssuranceLevel::QualifiedQes => "qualified_qes",
    }
}

fn parse_assurance(raw: &str) -> Result<AssuranceLevel, LedgerError> {
    match raw {
        "local_key" => Ok(AssuranceLevel::LocalKey),
        "crypto_wallet" => Ok(AssuranceLevel::CryptoWallet),
        "passkey" => Ok(AssuranceLevel::Passkey),
        "substantial_eidas" => Ok(AssuranceLevel::SubstantialEidas),
        "qualified_qes" => Ok(AssuranceLevel::QualifiedQes),
        other => Err(LedgerError::Integrity(format!(
            "unknown revocation assurance '{other}'"
        ))),
    }
}

fn validate_signature_hex(raw: &str) -> Result<(), LedgerError> {
    if raw.is_empty()
        || !raw.len().is_multiple_of(2)
        || !raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LedgerError::Integrity(
            "invalid revocation signature_hex: expected non-empty even lowercase hex".to_string(),
        ));
    }
    Ok(())
}

/// Persists a validated revocation into the hash-chained `revocations` table inside `tx`.
///
/// Idempotent when the exact same revocation envelope is already persisted; fails closed on any
/// conflicting envelope for the same [`RevocationId`] or invalid proof/hex metadata.
pub(crate) fn record_revocation_tx(
    tx: &Transaction<'_>,
    verified: &VerifiedRevocation,
    signature_hex: &str,
) -> Result<(RevocationId, Option<[u8; 32]>), LedgerError> {
    let revocation_id = validate_verified_revocation(verified)
        .map_err(|err| LedgerError::Integrity(format!("invalid revocation: {err}")))?;
    validate_signature_hex(signature_hex)?;

    let canonical_words = render_canonical_revocation(&verified.ast);
    let revocation_id_str = revocation_id.to_string();
    let assurance_str = format_assurance(verified.proof.assurance);
    let actor_kind_str = format_actor_kind(verified.proof.actor_kind);
    let signer_key_str = verified.proof.signer_key.to_string();

    if let Some(existing) = load_existing_revocation_by_id(tx, &revocation_id_str)? {
        let same_envelope = existing
            == (
                canonical_words.clone(),
                verified.proof.anchor_id.clone(),
                assurance_str.to_string(),
                actor_kind_str.to_string(),
                signer_key_str.clone(),
                verified.proof.valid_from,
                verified.proof.valid_until,
                signature_hex.to_string(),
            );
        if same_envelope {
            return Ok((revocation_id, None));
        }
        return Err(LedgerError::Integrity(format!(
            "revocation {revocation_id} already recorded with conflicting envelope metadata"
        )));
    }

    let existing_count: i64 =
        tx.query_row("SELECT COUNT(*) FROM revocations", [], |row| row.get(0))?;
    verify_sqlite_sequence_hwm(tx, "revocations", existing_count)?;
    let prev_entry_hash = load_latest_revocation_hash(tx)?;
    let entry_hash = compute_revocation_entry_hash(&EntryHashInput {
        prev_entry_hash,
        revocation_id,
        canonical_words: &canonical_words,
        anchor_id: &verified.proof.anchor_id,
        assurance: assurance_str,
        actor_kind: actor_kind_str,
        signer_key: &signer_key_str,
        valid_from: verified.proof.valid_from,
        valid_until: verified.proof.valid_until,
        signature_hex,
    });

    tx.execute(
        "INSERT INTO revocations (
            prev_entry_hash, entry_hash, revocation_id, canonical_words,
            anchor_id, assurance, actor_kind, signer_key,
            valid_from, valid_until, signature_hex
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            prev_entry_hash.map(|id| id.to_string()),
            entry_hash.to_string(),
            revocation_id_str,
            canonical_words,
            verified.proof.anchor_id,
            assurance_str,
            actor_kind_str,
            signer_key_str,
            verified.proof.valid_from,
            verified.proof.valid_until,
            signature_hex,
        ],
    )?;
    Ok((revocation_id, Some(*entry_hash.as_bytes())))
}

type ExistingEnvelopeTuple = (String, String, String, String, String, i64, i64, String);

fn load_existing_revocation_by_id(
    tx: &Transaction<'_>,
    revocation_id_str: &str,
) -> Result<Option<ExistingEnvelopeTuple>, LedgerError> {
    let mut stmt = tx.prepare(
        "SELECT canonical_words, anchor_id, assurance, actor_kind,
                signer_key, valid_from, valid_until, signature_hex
         FROM revocations
         WHERE revocation_id = ?1",
    )?;
    let mut rows = stmt.query(params![revocation_id_str])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some((
        col_text(row, 0, "revocations.canonical_words")?,
        col_text(row, 1, "revocations.anchor_id")?,
        col_text(row, 2, "revocations.assurance")?,
        col_text(row, 3, "revocations.actor_kind")?,
        col_text(row, 4, "revocations.signer_key")?,
        col_i64(row, 5, "revocations.valid_from")?,
        col_i64(row, 6, "revocations.valid_until")?,
        col_text(row, 7, "revocations.signature_hex")?,
    )))
}

fn load_latest_revocation_hash(tx: &Transaction<'_>) -> Result<Option<MandateId>, LedgerError> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT entry_hash FROM revocations ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match raw {
        None => Ok(None),
        Some(s) => MandateId::parse(&s).map(Some).map_err(|err| {
            LedgerError::Integrity(format!("corrupt latest revocation entry_hash: {err}"))
        }),
    }
}

/// Verifies `revocations` `seq` contiguity (`1..=count`), hash-chain continuity from genesis
/// (`None`) to tip, every `entry_hash`, canonical `HANDFEST REVOKE v1` syntax and `RevocationId`,
/// proof invariants, and `sqlite_sequence` high-water mark, returning all stored revocations and
/// the corresponding [`RevocationSnapshot`].
pub(crate) fn verify_and_load_revocations(
    conn: &Connection,
) -> Result<(Vec<StoredRevocation>, RevocationSnapshot), LedgerError> {
    verify_and_load_revocations_inner(conn, None)
}

pub(crate) fn verify_and_load_revocations_inner(
    conn: &Connection,
    mut collect_entry_hashes: Option<&mut Vec<[u8; 32]>>,
) -> Result<(Vec<StoredRevocation>, RevocationSnapshot), LedgerError> {
    let mut stmt = conn.prepare(
        "SELECT seq, prev_entry_hash, entry_hash, revocation_id, canonical_words,
                anchor_id, assurance, actor_kind, signer_key,
                valid_from, valid_until, signature_hex
         FROM revocations
         ORDER BY seq ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut expected_prev: Option<MandateId> = None;
    let mut expected_seq: i64 = 1;
    let mut stored = Vec::new();
    let mut snapshot = RevocationSnapshot::new();

    while let Some(row) = rows.next()? {
        let seq = col_i64(row, 0, "revocations.seq")?;
        if seq != expected_seq {
            return Err(LedgerError::Integrity(format!(
                "non-contiguous revocation seq: expected {expected_seq}, got {seq}"
            )));
        }
        let (entry_hash, record) = reconstruct_and_verify_revocation_row(row, seq, expected_prev)?;
        snapshot.insert(record.verified.clone()).map_err(|err| {
            LedgerError::Integrity(format!(
                "revocation seq {seq}: invalid proof binding: {err}"
            ))
        })?;
        stored.push(record);
        if let Some(hashes) = collect_entry_hashes.as_deref_mut() {
            hashes.push(*entry_hash.as_bytes());
        }
        expected_prev = Some(entry_hash);
        expected_seq += 1;
    }

    verify_sqlite_sequence_hwm(conn, "revocations", expected_seq - 1)?;
    Ok((stored, snapshot))
}

fn reconstruct_and_verify_revocation_row(
    row: &Row<'_>,
    seq: i64,
    expected_prev: Option<MandateId>,
) -> Result<(MandateId, StoredRevocation), LedgerError> {
    let prev_raw = col_opt_text(row, 1, "revocations.prev_entry_hash")?;
    let entry_hash_raw = col_text(row, 2, "revocations.entry_hash")?;
    let revocation_id_raw = col_text(row, 3, "revocations.revocation_id")?;
    let canonical_words = col_text(row, 4, "revocations.canonical_words")?;
    let anchor_id = col_text(row, 5, "revocations.anchor_id")?;
    let assurance_raw = col_text(row, 6, "revocations.assurance")?;
    let actor_kind_raw = col_text(row, 7, "revocations.actor_kind")?;
    let signer_key_raw = col_text(row, 8, "revocations.signer_key")?;
    let valid_from = col_i64(row, 9, "revocations.valid_from")?;
    let valid_until = col_i64(row, 10, "revocations.valid_until")?;
    let signature_hex = col_text(row, 11, "revocations.signature_hex")?;

    let prev_entry_hash = parse_optional_mandate_id(seq, "revocations.prev_entry_hash", prev_raw)?;
    if prev_entry_hash != expected_prev {
        return Err(LedgerError::Integrity(format!(
            "revocation seq {seq}: broken prev_entry_hash link (expected {expected_prev:?}, got {prev_entry_hash:?})"
        )));
    }
    let stored_entry_hash = MandateId::parse(&entry_hash_raw).map_err(|err| {
        LedgerError::Integrity(format!("revocation seq {seq}: invalid entry_hash: {err}"))
    })?;
    let revocation_id = RevocationId::parse(&revocation_id_raw).map_err(|err| {
        LedgerError::Integrity(format!(
            "revocation seq {seq}: invalid revocation_id: {err}"
        ))
    })?;
    let ast = parse_canonical_revocation(&canonical_words).map_err(|err| {
        LedgerError::Integrity(format!(
            "revocation seq {seq}: non-canonical or invalid revocation text: {err}"
        ))
    })?;
    let computed_rev_id = ast.revocation_id();
    if computed_rev_id != revocation_id {
        return Err(LedgerError::Integrity(format!(
            "revocation seq {seq}: revocation_id mismatch (stored {revocation_id}, computed {computed_rev_id})"
        )));
    }
    let assurance = parse_assurance(&assurance_raw)?;
    let actor_kind = parse_actor_kind(&actor_kind_raw)?;
    let signer_key = KeyId::parse(&signer_key_raw).map_err(|err| {
        LedgerError::Integrity(format!("revocation seq {seq}: invalid signer_key: {err}"))
    })?;
    validate_signature_hex(&signature_hex)?;

    let computed_entry_hash = compute_revocation_entry_hash(&EntryHashInput {
        prev_entry_hash,
        revocation_id,
        canonical_words: &canonical_words,
        anchor_id: &anchor_id,
        assurance: &assurance_raw,
        actor_kind: &actor_kind_raw,
        signer_key: &signer_key_raw,
        valid_from,
        valid_until,
        signature_hex: &signature_hex,
    });
    if computed_entry_hash != stored_entry_hash {
        return Err(LedgerError::Integrity(format!(
            "revocation seq {seq}: entry_hash mismatch (stored {stored_entry_hash}, computed {computed_entry_hash})"
        )));
    }

    let verified = VerifiedRevocation {
        ast,
        proof: VerifiedAnchorProof {
            anchor_id,
            assurance,
            signer_key,
            actor_kind,
            valid_from,
            valid_until,
        },
    };
    Ok((
        stored_entry_hash,
        StoredRevocation {
            revocation_id,
            verified,
            signature_hex,
        },
    ))
}
