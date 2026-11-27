//! Bounded, fail-closed newline-delimited JSON protocol for `handfest-approver`.

use std::fmt;
use std::io::{self, BufRead, Write};

use handfest_anchors::SignedMandate;
use handfest_core::ast::is_valid_timestamp;
use handfest_core::exact_json::parse_exact_json;
use handfest_core::gate::{validate_proof_shape, ProofShapeError};
use serde::{Deserialize, Serialize};

/// Maximum wire frame size for a client [`SignRequest`] (56 KiB, excluding trailing `\n`).
///
/// Strictly smaller than [`MAX_RESPONSE_FRAME_BYTES`] so any valid request leaves guaranteed
/// headroom for signature and envelope metadata in [`SignResponse::Approved`].
pub const MAX_REQUEST_FRAME_BYTES: usize = 56 * 1024;

/// Maximum wire frame size for a daemon [`SignResponse`] (64 KiB, excluding trailing `\n`).
pub const MAX_RESPONSE_FRAME_BYTES: usize = 64 * 1024;

/// Maximum wire frame size in bytes (64 KiB, excluding trailing `\n`), equal to
/// [`MAX_RESPONSE_FRAME_BYTES`].
pub const MAX_FRAME_BYTES: usize = MAX_RESPONSE_FRAME_BYTES;

/// Upper bound on bytes drained from an oversized line tail before giving up.
const MAX_OVERSIZED_DRAIN_BYTES: usize = 1024 * 1024;

/// Machine-readable error code: frame exceeded maximum allowed byte length.
pub const ERR_FRAME_TOO_LARGE: &str = "frame_too_large";
/// Machine-readable error code: malformed wire frame (invalid UTF-8, control byte, EOF, bad JSON).
pub const ERR_INVALID_FRAME: &str = "invalid_frame";
/// Machine-readable error code: semantically invalid `SignRequest` fields or validity window.
pub const ERR_INVALID_REQUEST: &str = "invalid_request";
/// Machine-readable error code: mandate draft failed `HANDFEST v1` parsing or validation.
pub const ERR_INVALID_MANDATE: &str = "invalid_mandate";
/// Machine-readable error code: mandate `FROM` key does not match the daemon's configured signer.
pub const ERR_SIGNER_MISMATCH: &str = "signer_mismatch";
/// Machine-readable error code: human approval prompt failed before producing a decision.
pub const ERR_PROMPT_FAILED: &str = "prompt_failed";
/// Machine-readable error code: cryptographic signing backend failed after approval.
pub const ERR_SIGNING_FAILED: &str = "signing_failed";
/// Machine-readable error code: request exceeded the configured daemon timeout.
pub const ERR_TIMEOUT: &str = "timeout";
/// Machine-readable error code: internal daemon error (e.g. response exceeded maximum frame size).
pub const ERR_INTERNAL: &str = "internal_error";

/// Request sent by an untrusted client over the Unix domain socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub mandate_text: String,
    pub valid_from: i64,
    pub valid_until: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_id: Option<String>,
}

impl SignRequest {
    /// Validates fail-closed wire and semantic invariants before parsing or prompting.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.mandate_text.trim().is_empty() {
            return Err(ProtocolError::InvalidRequest(
                "mandate_text must not be empty".to_string(),
            ));
        }
        if let Some(ch) = find_forbidden_mandate_char(&self.mandate_text) {
            return Err(ProtocolError::ControlChar(format!(
                "mandate_text contains forbidden character U+{:04X}",
                u32::from(ch)
            )));
        }
        if !is_valid_timestamp(self.valid_from) {
            return Err(ProtocolError::InvalidRequest(format!(
                "valid_from {} outside RFC 3339 4-digit-year bounds",
                self.valid_from
            )));
        }
        if !is_valid_timestamp(self.valid_until) {
            return Err(ProtocolError::InvalidRequest(format!(
                "valid_until {} outside RFC 3339 4-digit-year bounds",
                self.valid_until
            )));
        }
        if self.valid_from > self.valid_until {
            return Err(ProtocolError::InvalidValidityWindow {
                valid_from: self.valid_from,
                valid_until: self.valid_until,
            });
        }
        if let Some(anchor_id) = self.anchor_id.as_deref() {
            validate_single_line_text(anchor_id, "anchor_id")?;
            validate_proof_shape(anchor_id, self.valid_from, self.valid_until)
                .map_err(map_proof_shape_error)?;
        }
        Ok(())
    }
}

/// Response returned by `handfest-approver` for a single [`SignRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignResponse {
    Approved { signed_mandate: SignedMandate },
    Denied { reason: String },
    Error { code: String, message: String },
}

impl SignResponse {
    /// Validates structural invariants of a decoded [`SignResponse`].
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Approved { signed_mandate } => validate_signed_mandate(signed_mandate),
            Self::Denied { reason } => validate_single_line_text(reason, "denied reason"),
            Self::Error { code, message } => {
                validate_single_line_text(code, "error code")?;
                validate_single_line_text(message, "error message")
            }
        }
    }
}

/// Structured protocol framing and decoding errors.
#[derive(Debug)]
pub enum ProtocolError {
    FrameTooLarge { max_bytes: usize },
    StreamPoisoned,
    TruncatedFrame,
    InvalidUtf8,
    ControlChar(String),
    InvalidJson(String),
    InvalidValidityWindow { valid_from: i64, valid_until: i64 },
    InvalidRequest(String),
    Io(io::Error),
}

impl ProtocolError {
    /// Maps this error to a stable machine-readable wire error code.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::FrameTooLarge { .. } => ERR_FRAME_TOO_LARGE,
            Self::StreamPoisoned
            | Self::TruncatedFrame
            | Self::InvalidUtf8
            | Self::InvalidJson(_) => ERR_INVALID_FRAME,
            Self::ControlChar(_) | Self::InvalidValidityWindow { .. } | Self::InvalidRequest(_) => {
                ERR_INVALID_REQUEST
            }
            Self::Io(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                ERR_TIMEOUT
            }
            Self::Io(_) => ERR_INVALID_FRAME,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { max_bytes } => {
                write!(f, "wire frame exceeded maximum size of {max_bytes} bytes")
            }
            Self::StreamPoisoned => {
                f.write_str("wire stream is poisoned after incomplete frame I/O or EOF")
            }
            Self::TruncatedFrame => f.write_str("wire frame ended with EOF before newline"),
            Self::InvalidUtf8 => f.write_str("wire frame is not valid UTF-8"),
            Self::ControlChar(detail) => write!(f, "forbidden control character: {detail}"),
            Self::InvalidJson(detail) => write!(f, "invalid JSON frame: {detail}"),
            Self::InvalidValidityWindow {
                valid_from,
                valid_until,
            } => write!(
                f,
                "invalid validity window: valid_from ({valid_from}) > valid_until ({valid_until})"
            ),
            Self::InvalidRequest(detail) => write!(f, "invalid sign request: {detail}"),
            Self::Io(err) => write!(f, "protocol I/O error: {err}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoisonState {
    None,
    Oversized { max_bytes: usize },
    PartialLineIo,
}

/// Stateful bounded wire frame reader that permanently poisons itself if an oversized line cannot
/// be fully drained to `\n` within [`MAX_OVERSIZED_DRAIN_BYTES`] (including EOF before `\n`), or
/// if a non-`Interrupted` I/O error or EOF occurs mid-line after bytes have already been consumed.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    poisoned: PoisonState,
}

impl<R: BufRead> FrameReader<R> {
    /// Wraps `inner` in a fail-closed bounded [`FrameReader`].
    #[must_use]
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            poisoned: PoisonState::None,
        }
    }

    /// Returns `true` if a prior oversized frame could not be fully drained to `\n` or a
    /// partial-line I/O error / mid-line EOF poisoned the stream.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        !matches!(self.poisoned, PoisonState::None)
    }

    /// Reads one bounded `\n`-terminated UTF-8 wire frame without unbounded allocation.
    ///
    /// Returns `Ok(None)` strictly on clean EOF before any bytes are read.
    /// Fails closed on oversized lines (draining the remainder up to `\n` or poisoning this reader
    /// permanently if the bounded drain limit is reached so no tail can ever be smuggled as a
    /// subsequent frame), partial-line I/O errors (poisoning the reader so the corrupt tail can
    /// never be read as a new frame), truncated frames (EOF without `\n`), invalid UTF-8, bare
    /// `\r`, NUL (`0x00`), or any other ASCII control character on the wire line.
    pub fn read_frame_line(&mut self, max_bytes: usize) -> Result<Option<String>, ProtocolError> {
        match self.poisoned {
            PoisonState::None => {}
            PoisonState::Oversized {
                max_bytes: poisoned_max,
            } => {
                return Err(ProtocolError::FrameTooLarge {
                    max_bytes: poisoned_max,
                });
            }
            PoisonState::PartialLineIo => return Err(ProtocolError::StreamPoisoned),
        }
        let mut buf = Vec::new();
        loop {
            let chunk = match self.inner.fill_buf() {
                Ok(chunk) => chunk,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    if !buf.is_empty() {
                        self.poisoned = PoisonState::PartialLineIo;
                    }
                    return Err(ProtocolError::Io(err));
                }
            };
            if chunk.is_empty() {
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    self.poisoned = PoisonState::PartialLineIo;
                    Err(ProtocolError::TruncatedFrame)
                };
            }

            if let Some(nl_pos) = chunk.iter().position(|&b| b == b'\n') {
                if buf.len().saturating_add(nl_pos) > max_bytes {
                    self.inner.consume(nl_pos + 1);
                    return Err(ProtocolError::FrameTooLarge { max_bytes });
                }
                buf.extend_from_slice(&chunk[..nl_pos]);
                self.inner.consume(nl_pos + 1);
                return finalize_wire_line(buf);
            }

            let chunk_len = chunk.len();
            if buf.len().saturating_add(chunk_len) > max_bytes {
                let excess = buf.len().saturating_add(chunk_len) - max_bytes;
                let remaining_drain = MAX_OVERSIZED_DRAIN_BYTES.saturating_sub(excess);
                self.inner.consume(chunk_len);
                if !drain_oversized_line(&mut self.inner, remaining_drain) {
                    self.poisoned = PoisonState::Oversized { max_bytes };
                }
                return Err(ProtocolError::FrameTooLarge { max_bytes });
            }
            buf.extend_from_slice(chunk);
            self.inner.consume(chunk_len);
        }
    }
}

fn drain_oversized_line<R: BufRead>(reader: &mut R, max_drain: usize) -> bool {
    let mut drained = 0usize;
    while drained < max_drain {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        };
        if chunk.is_empty() {
            return false;
        }
        let remaining = max_drain - drained;
        if let Some(nl_pos) = chunk.iter().position(|&b| b == b'\n') {
            if nl_pos < remaining {
                reader.consume(nl_pos + 1);
                return true;
            }
            reader.consume(remaining);
            return false;
        }
        let take = chunk.len().min(remaining);
        reader.consume(take);
        drained += take;
    }
    false
}

/// Serializes `value` as a single bounded `\n`-terminated JSON frame and flushes `writer`.
pub fn write_frame<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    max_bytes: usize,
) -> Result<(), ProtocolError> {
    let encoded =
        serde_json::to_string(value).map_err(|err| ProtocolError::InvalidJson(err.to_string()))?;
    if encoded.len() > max_bytes {
        return Err(ProtocolError::FrameTooLarge { max_bytes });
    }
    validate_wire_line_bytes(encoded.as_bytes())?;
    writer
        .write_all(encoded.as_bytes())
        .map_err(ProtocolError::Io)?;
    writer.write_all(b"\n").map_err(ProtocolError::Io)?;
    writer.flush().map_err(ProtocolError::Io)
}

/// Parses and validates a [`SignRequest`] from a single wire frame line.
pub fn decode_sign_request(line: &str) -> Result<SignRequest, ProtocolError> {
    validate_decoded_wire_line(line, MAX_REQUEST_FRAME_BYTES)?;
    let req: SignRequest =
        serde_json::from_str(line).map_err(|err| ProtocolError::InvalidJson(err.to_string()))?;
    req.validate()?;
    Ok(req)
}

/// Parses and validates a [`SignResponse`] from a single wire frame line.
pub fn decode_sign_response(line: &str) -> Result<SignResponse, ProtocolError> {
    validate_decoded_wire_line(line, MAX_RESPONSE_FRAME_BYTES)?;
    let resp: SignResponse =
        serde_json::from_str(line).map_err(|err| ProtocolError::InvalidJson(err.to_string()))?;
    resp.validate()?;
    Ok(resp)
}

/// Returns `true` for Unicode line/paragraph separators and Bidi formatting controls that can
/// spoof WYSIWYS mandate or identifier rendering in terminals and desktop dialogs.
pub(crate) const fn is_forbidden_wysiwys_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn finalize_wire_line(buf: Vec<u8>) -> Result<Option<String>, ProtocolError> {
    validate_wire_line_bytes(&buf)?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| ProtocolError::InvalidUtf8)
}

fn validate_decoded_wire_line(line: &str, max_bytes: usize) -> Result<(), ProtocolError> {
    if line.len() > max_bytes {
        return Err(ProtocolError::FrameTooLarge { max_bytes });
    }
    validate_wire_line_bytes(line.as_bytes())?;
    // Reuse `handfest-core`'s strict parser to reject duplicate JSON keys and excessive depth.
    parse_exact_json(line).map_err(|err| ProtocolError::InvalidJson(err.to_string()))?;
    Ok(())
}

fn validate_wire_line_bytes(bytes: &[u8]) -> Result<(), ProtocolError> {
    for &b in bytes {
        if b < 0x20 || b == 0x7f {
            return Err(ProtocolError::ControlChar(format!(
                "raw wire byte 0x{b:02X} is not allowed in JSON frame"
            )));
        }
    }
    Ok(())
}

pub(crate) fn find_forbidden_mandate_char(text: &str) -> Option<char> {
    text.chars()
        .find(|&c| (c.is_control() && c != '\n') || is_forbidden_wysiwys_char(c))
}

fn find_forbidden_single_line_char(text: &str) -> Option<char> {
    text.chars()
        .find(|&c| c.is_control() || is_forbidden_wysiwys_char(c))
}

pub(crate) fn validate_single_line_text(text: &str, field: &str) -> Result<(), ProtocolError> {
    if text.trim().is_empty() {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    if let Some(ch) = find_forbidden_single_line_char(text) {
        return Err(ProtocolError::ControlChar(format!(
            "{field} contains forbidden character U+{:04X}",
            u32::from(ch)
        )));
    }
    Ok(())
}

fn validate_signed_mandate(signed: &SignedMandate) -> Result<(), ProtocolError> {
    if signed.canonical_words.trim().is_empty() {
        return Err(ProtocolError::InvalidRequest(
            "signed_mandate.canonical_words must not be empty".to_string(),
        ));
    }
    if let Some(ch) = find_forbidden_mandate_char(&signed.canonical_words) {
        return Err(ProtocolError::ControlChar(format!(
            "signed_mandate.canonical_words contains forbidden character U+{:04X}",
            u32::from(ch)
        )));
    }
    validate_single_line_text(&signed.anchor_id, "signed_mandate.anchor_id")?;
    validate_proof_shape(&signed.anchor_id, signed.valid_from, signed.valid_until)
        .map_err(map_proof_shape_error)?;
    validate_single_line_text(&signed.assurance, "signed_mandate.assurance")?;
    validate_single_line_text(&signed.actor_kind, "signed_mandate.actor_kind")?;
    validate_single_line_text(&signed.signer_key, "signed_mandate.signer_key")?;
    validate_single_line_text(&signed.signature_hex, "signed_mandate.signature_hex")?;
    Ok(())
}

fn map_proof_shape_error(err: ProofShapeError) -> ProtocolError {
    match err {
        ProofShapeError::EmptyAnchorId => {
            ProtocolError::InvalidRequest("anchor_id must not be empty".to_string())
        }
        ProofShapeError::InvalidAnchorIdChars => ProtocolError::ControlChar(
            "anchor_id contains forbidden control or quote characters".to_string(),
        ),
        ProofShapeError::TimestampOutOfRange(ts) => ProtocolError::InvalidRequest(format!(
            "timestamp {ts} outside RFC 3339 4-digit-year bounds"
        )),
        ProofShapeError::InvertedValidityWindow {
            valid_from,
            valid_until,
        } => ProtocolError::InvalidValidityWindow {
            valid_from,
            valid_until,
        },
    }
}
