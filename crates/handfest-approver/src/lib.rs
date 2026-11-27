//! Out-of-band WYSIWYS signing daemon (`handfest-approver`) and Unix domain socket client.
//!
//! Security boundary:
//! - Untrusted AI agents connect to a restricted Unix domain socket and submit a draft
//!   [`protocol::SignRequest`].
//! - The daemon independently parses and canonically renders the `HANDFEST v1` mandate via
//!   `handfest-core::cnl`, verifies `FROM` matches the daemon's [`handfest_anchors::MandateSigner`],
//!   renders a verbatim canonical [`prompt::WysiwysPromptView`] to the human through a pluggable
//!   [`prompt::ApprovalPrompt`], and invokes the signer strictly on explicit approval.

use std::time::Duration;

#[cfg(unix)]
pub mod client;
#[cfg(unix)]
pub mod daemon;
pub mod prompt;
pub mod protocol;
pub mod signer;
#[cfg(unix)]
mod socket;

/// Maximum supported finite request or daemon timeout (24 hours).
///
/// Bounded to stay safely representable in 32-bit/64-bit `timeval.tv_sec`,
/// Linux socket timeout jiffies, and `Instant::checked_add` on all Unix platforms.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(86_400);

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeoutValidationError {
    Zero,
    ExceedsMax,
}

/// Validates a CLI `--timeout-secs` flag against `(0, MAX_TIMEOUT]`.
#[cfg(unix)]
pub fn validate_timeout_secs(secs: u64) -> Result<Duration, String> {
    validate_finite_timeout(Duration::from_secs(secs)).map_err(|err| match err {
        TimeoutValidationError::Zero => "--timeout-secs must be greater than 0".to_string(),
        TimeoutValidationError::ExceedsMax => {
            format!("--timeout-secs must not exceed {}", MAX_TIMEOUT.as_secs())
        }
    })
}

#[cfg(unix)]
pub(crate) fn validate_finite_timeout(
    timeout: Duration,
) -> Result<Duration, TimeoutValidationError> {
    if timeout.is_zero() {
        return Err(TimeoutValidationError::Zero);
    }
    if timeout > MAX_TIMEOUT {
        return Err(TimeoutValidationError::ExceedsMax);
    }
    Ok(timeout)
}
