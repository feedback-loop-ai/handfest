//! Append-only JSONL checkpoint sidecar persistence, validation, and atomic rollback helpers.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use handfest_core::ast::{encode_lower_hex, MandateId};

use crate::preflight_open::{
    open_no_follow_append_0600, open_no_follow_read_only, HAS_UNIX_O_NOFOLLOW,
};
use crate::witness::{
    validate_proof_shape, LedgerCheckpoint, StoredCheckpoint, EMPTY_RECEIPT_TIP_HASH,
};
use crate::{LedgerChainHashes, LedgerError};

/// Result of reading a checkpoint sidecar file before ledger verification.
#[derive(Debug)]
pub(crate) enum SidecarLoad {
    Missing,
    Empty,
    Records(Vec<StoredCheckpoint>),
}

/// RAII rollback guard for an appended checkpoint sidecar record.
///
/// If dropped without calling [`Self::commit`] (for example when writing/flushing/syncing the
/// sidecar fails or when SQLite `tx.commit()` fails), truncates the sidecar back to `orig_len`
/// and `sync_all()`s it (removing newly created 0-byte files) so no orphan or partial JSONL line
/// is ever left behind.
#[derive(Debug)]
pub(crate) struct PendingSidecarAppend {
    path: PathBuf,
    file: Option<fs::File>,
    orig_len: u64,
    created_new: bool,
    committed: bool,
}

impl PendingSidecarAppend {
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingSidecarAppend {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(file) = self.file.take() {
            let _ = file.set_len(self.orig_len);
            let _ = file.sync_all();
            drop(file);
            if self.created_new && self.orig_len == 0 {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

pub(crate) fn validate_stored_checkpoint_chain(
    records: &[StoredCheckpoint],
) -> Result<(), LedgerError> {
    let mut expected_prev: Option<&str> = None;
    let mut prev_cp: Option<&LedgerCheckpoint> = None;

    for (idx, record) in records.iter().enumerate() {
        let expected_seq = u64::try_from(idx + 1)
            .map_err(|_| LedgerError::Integrity("checkpoint seq overflow".to_string()))?;
        if record.seq != expected_seq {
            return Err(LedgerError::Integrity(format!(
                "non-contiguous checkpoint seq: expected {expected_seq}, got {}",
                record.seq
            )));
        }
        if record.prev_record_hash.as_deref() != expected_prev {
            return Err(LedgerError::Integrity(format!(
                "checkpoint seq {}: broken prev_record_hash link",
                record.seq
            )));
        }
        MandateId::parse(&record.record_hash).map_err(|err| {
            LedgerError::Integrity(format!(
                "checkpoint seq {}: invalid record_hash '{}': {err}",
                record.seq, record.record_hash
            ))
        })?;
        validate_proof_shape(&record.checkpoint, &record.proof)?;

        let expected_hash = StoredCheckpoint::compute_record_hash(
            record.seq,
            record.prev_record_hash.as_deref(),
            &record.checkpoint,
            &record.proof,
        );
        if record.record_hash != expected_hash {
            return Err(LedgerError::Integrity(format!(
                "checkpoint seq {}: record_hash mismatch (stored {}, computed {expected_hash})",
                record.seq, record.record_hash
            )));
        }
        if record.checkpoint.receipt_seq == 0 && record.checkpoint.revocation_seq == 0 {
            return Err(LedgerError::Integrity(format!(
                "checkpoint seq {}: empty (0, 0) checkpoint is unanchorable",
                record.seq
            )));
        }
        if let Some(prev) = prev_cp {
            ensure_monotonic_checkpoint(record.seq, prev, &record.checkpoint)?;
        }
        expected_prev = Some(record.record_hash.as_str());
        prev_cp = Some(&record.checkpoint);
    }
    Ok(())
}

pub(crate) fn ensure_monotonic_checkpoint(
    seq: u64,
    prev: &LedgerCheckpoint,
    curr: &LedgerCheckpoint,
) -> Result<(), LedgerError> {
    if curr.receipt_seq < prev.receipt_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {seq}: non-monotonic receipt_seq {} < previous {}",
            curr.receipt_seq, prev.receipt_seq
        )));
    }
    if curr.revocation_seq < prev.revocation_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {seq}: non-monotonic revocation_seq {} < previous {}",
            curr.revocation_seq, prev.revocation_seq
        )));
    }
    if curr.receipt_seq == prev.receipt_seq && curr.revocation_seq == prev.revocation_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {seq}: zero-progress duplicate checkpoint ({}, {})",
            curr.receipt_seq, curr.revocation_seq
        )));
    }
    Ok(())
}

fn reject_symlink_without_o_nofollow(path: &Path) -> Result<(), LedgerError> {
    if HAS_UNIX_O_NOFOLLOW {
        return Ok(());
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(LedgerError::Integrity(format!(
                "checkpoint sidecar '{}' must not be a symlink",
                path.display()
            )));
        }
    }
    Ok(())
}

fn classify_sidecar_open_error(path: &Path, action: &str, err: &io::Error) -> LedgerError {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return LedgerError::Integrity(format!(
                "checkpoint sidecar '{}' must not be a symlink: {err}",
                path.display()
            ));
        }
        if !meta.file_type().is_file() {
            return LedgerError::Integrity(format!(
                "checkpoint sidecar '{}' must be a regular file (not FIFO/dir/socket): {err}",
                path.display()
            ));
        }
    }
    LedgerError::Storage(format!(
        "failed to {action} checkpoint sidecar '{}': {err}",
        path.display()
    ))
}

fn ensure_regular_sidecar_file(file: &fs::File, path: &Path) -> Result<u64, LedgerError> {
    let meta = file.metadata().map_err(|err| {
        LedgerError::Storage(format!(
            "failed to fstat checkpoint sidecar '{}': {err}",
            path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(LedgerError::Integrity(format!(
            "checkpoint sidecar '{}' must be a regular file (not FIFO/dir/socket)",
            path.display()
        )));
    }
    Ok(meta.len())
}

pub(crate) fn load_checkpoints_from_file_status(path: &Path) -> Result<SidecarLoad, LedgerError> {
    reject_symlink_without_o_nofollow(path)?;
    let mut file = match open_no_follow_read_only(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(SidecarLoad::Missing),
        Err(err) => return Err(classify_sidecar_open_error(path, "open", &err)),
    };
    let _ = ensure_regular_sidecar_file(&file, path)?;

    let mut raw = String::new();
    match file.read_to_string(&mut raw) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            return Err(LedgerError::Integrity(format!(
                "checkpoint sidecar '{}' contains invalid UTF-8: {err}",
                path.display()
            )));
        }
        Err(err) => {
            return Err(LedgerError::Storage(format!(
                "failed to read checkpoint sidecar '{}': {err}",
                path.display()
            )));
        }
    }

    if raw.is_empty() {
        return Ok(SidecarLoad::Empty);
    }
    Ok(SidecarLoad::Records(parse_and_validate_sidecar_text(
        path, &raw,
    )?))
}

fn parse_and_validate_sidecar_text(
    path: &Path,
    raw: &str,
) -> Result<Vec<StoredCheckpoint>, LedgerError> {
    if !raw.ends_with('\n') {
        return Err(LedgerError::Integrity(format!(
            "checkpoint sidecar '{}' missing trailing newline (possible partial write or truncation)",
            path.display()
        )));
    }

    let mut records = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        if line.is_empty() {
            return Err(LedgerError::Integrity(format!(
                "checkpoint sidecar '{}' contains empty line at line {}",
                path.display(),
                idx + 1
            )));
        }
        let record: StoredCheckpoint = serde_json::from_str(line).map_err(|err| {
            LedgerError::Integrity(format!(
                "checkpoint sidecar '{}' line {} invalid JSON: {err}",
                path.display(),
                idx + 1
            ))
        })?;
        records.push(record);
    }

    validate_stored_checkpoint_chain(&records)?;
    Ok(records)
}

pub(crate) fn append_checkpoint_to_file(
    path: &Path,
    record: &StoredCheckpoint,
) -> Result<PendingSidecarAppend, LedgerError> {
    let mut line = serde_json::to_string(record)?;
    line.push('\n');

    reject_symlink_without_o_nofollow(path)?;
    let created_new = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(err) if err.kind() == io::ErrorKind::NotFound => true,
        Err(err) => return Err(classify_sidecar_open_error(path, "stat", &err)),
    };
    let file = open_no_follow_append_0600(path)
        .map_err(|err| classify_sidecar_open_error(path, "open for append", &err))?;
    let orig_len = ensure_regular_sidecar_file(&file, path)?;

    let mut pending = PendingSidecarAppend {
        path: path.to_path_buf(),
        file: Some(file),
        orig_len,
        created_new,
        committed: false,
    };

    {
        let file = pending
            .file
            .as_mut()
            .expect("pending sidecar append holds open file handle");
        file.write_all(line.as_bytes()).map_err(|err| {
            LedgerError::Storage(format!(
                "failed to write checkpoint sidecar '{}': {err}",
                path.display()
            ))
        })?;
        file.flush().map_err(|err| {
            LedgerError::Storage(format!(
                "failed to flush checkpoint sidecar '{}': {err}",
                path.display()
            ))
        })?;
        file.sync_all().map_err(|err| {
            LedgerError::Storage(format!(
                "failed to sync checkpoint sidecar '{}': {err}",
                path.display()
            ))
        })?;
    }

    Ok(pending)
}

pub(crate) fn build_checkpoint_from_hashes(
    chain_hashes: &LedgerChainHashes,
    timestamp: i64,
) -> Result<LedgerCheckpoint, LedgerError> {
    let receipt_seq = u64::try_from(chain_hashes.receipt_hashes.len())
        .map_err(|_| LedgerError::Integrity("receipt_seq overflow".to_string()))?;
    let receipt_hash = chain_hashes
        .receipt_hashes
        .last()
        .copied()
        .unwrap_or(EMPTY_RECEIPT_TIP_HASH);
    let revocation_seq = u64::try_from(chain_hashes.revocation_hashes.len())
        .map_err(|_| LedgerError::Integrity("revocation_seq overflow".to_string()))?;
    let revocation_tip_hash = chain_hashes.revocation_hashes.last().copied();
    Ok(LedgerCheckpoint {
        receipt_seq,
        receipt_hash,
        revocation_seq,
        revocation_tip_hash,
        timestamp,
    })
}

pub(crate) fn verify_checkpoint_matches_chain(
    seq: u64,
    cp: &LedgerCheckpoint,
    chain_hashes: &LedgerChainHashes,
) -> Result<(), LedgerError> {
    let local_receipts = u64::try_from(chain_hashes.receipt_hashes.len())
        .map_err(|_| LedgerError::Integrity("local receipt count overflow".to_string()))?;
    if local_receipts < cp.receipt_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {seq}: ledger rollback or truncation detected (anchored receipt_seq {}, local receipt count {local_receipts})",
            cp.receipt_seq
        )));
    }
    if cp.receipt_seq > 0 {
        let idx = usize::try_from(cp.receipt_seq - 1)
            .map_err(|_| LedgerError::Integrity("receipt_seq index overflow".to_string()))?;
        let actual = chain_hashes.receipt_hashes[idx];
        if actual != cp.receipt_hash {
            return Err(LedgerError::Integrity(format!(
                "checkpoint seq {seq}: receipt hash mismatch at receipt_seq {} (anchored {}, local {})",
                cp.receipt_seq,
                encode_lower_hex(&cp.receipt_hash),
                encode_lower_hex(&actual)
            )));
        }
    }

    let local_revocations = u64::try_from(chain_hashes.revocation_hashes.len())
        .map_err(|_| LedgerError::Integrity("local revocation count overflow".to_string()))?;
    if local_revocations < cp.revocation_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {seq}: revocation rollback or truncation detected (anchored revocation_seq {}, local revocation count {local_revocations})",
            cp.revocation_seq
        )));
    }
    if let Some(expected_rev) = cp.revocation_tip_hash {
        let idx = usize::try_from(cp.revocation_seq - 1)
            .map_err(|_| LedgerError::Integrity("revocation_seq index overflow".to_string()))?;
        let actual = chain_hashes.revocation_hashes[idx];
        if actual != expected_rev {
            return Err(LedgerError::Integrity(format!(
                "checkpoint seq {seq}: revocation tip hash mismatch at revocation_seq {} (anchored {}, local {})",
                cp.revocation_seq,
                encode_lower_hex(&expected_rev),
                encode_lower_hex(&actual)
            )));
        }
    }
    Ok(())
}
