//! Runtime safety gating for Diagnostic Trio.
//!
//! Trio is **read-only by default**.  All Discover probes and most Trace
//! interrogations read existing files or observe passively-available state and
//! never mutate the system.  A small set of interrogation paths is considered
//! *sensitive* — either because they observe privileged state (active session
//! data, payload content) or because they touch OS-level configuration outside
//! of the repository.  These paths require explicit authorization before Trio
//! will invoke them.
//!
//! # Safety levels
//!
//! | Level        | Meaning                                                     |
//! |--------------|-------------------------------------------------------------|
//! | `ReadOnly`   | Default.  Reads files and passively available host state.   |
//! | `Authorized` | Explicit opt-in.  Required for sensitive inspection paths.  |
//!
//! # Gating model
//!
//! Every potentially sensitive operation declares a `required` [`SafetyLevel`].
//! The caller holds a [`SafetyPolicy`] carrying the `granted` level.
//! [`check_gate`] returns `Ok(())` when `granted >= required`, or
//! `Err(SafetyViolation)` when the operation is not authorized.
//!
//! # Sensitive paths
//!
//! **Trace targets that require `Authorized`:**
//! - `Sessions` — observes active session credentials and handshake state.
//! - `PayloadOrProtocol` — deep packet / payload inspection.
//!
//! **Discover scopes that require `Authorized`:**
//! - `DiscoverScope::Host` — reads OS-level config files outside the repo.
//!
//! All other Trace targets and `DiscoverScope::Repository` are `ReadOnly`.
//!
//! # Provenance
//!
//! When Trio emits an [`crate::evidence::EvidenceRecord`] for a gated path the
//! `metadata` map will contain `"safety_level": "authorized"`.  For
//! read-only paths the key is absent to keep records concise.

use std::fmt;

/// Authorization level required to execute an inspection operation.
///
/// Levels are ordered: `ReadOnly < Authorized`.  A policy grants everything at
/// or below its own level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyLevel {
    /// Non-destructive read-only access.  Default for all operations.
    ReadOnly = 0,
    /// Explicit authorization required.  Must be consciously granted by the
    /// caller before sensitive inspection paths may run.
    Authorized = 1,
}

impl SafetyLevel {
    /// Canonical string label used in evidence metadata and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            SafetyLevel::ReadOnly => "read-only",
            SafetyLevel::Authorized => "authorized",
        }
    }
}

impl fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when an operation's required safety level exceeds the level
/// granted by the active [`SafetyPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyViolation {
    /// Human-readable name of the operation that was blocked.
    pub operation: String,
    /// The level the operation requires.
    pub required: SafetyLevel,
    /// The level that was actually granted.
    pub granted: SafetyLevel,
}

impl fmt::Display for SafetyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "safety gate blocked '{}': requires '{}' but only '{}' granted",
            self.operation,
            self.required.as_str(),
            self.granted.as_str(),
        )
    }
}

/// Caller-held policy object that carries the granted [`SafetyLevel`].
///
/// Construct via [`SafetyPolicy::read_only`] (default) or
/// [`SafetyPolicy::authorized`] (explicit opt-in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyPolicy {
    /// The level granted to operations running under this policy.
    pub level: SafetyLevel,
}

impl SafetyPolicy {
    /// Construct a read-only policy.  This is the safe default.
    pub fn read_only() -> Self {
        SafetyPolicy {
            level: SafetyLevel::ReadOnly,
        }
    }

    /// Construct an authorized policy.  Pass this only when the caller has
    /// explicitly confirmed that sensitive inspection is acceptable.
    pub fn authorized() -> Self {
        SafetyPolicy {
            level: SafetyLevel::Authorized,
        }
    }
}

impl Default for SafetyPolicy {
    /// The default policy is read-only, keeping Trio safe by default.
    fn default() -> Self {
        SafetyPolicy::read_only()
    }
}

/// Gate an operation against the active [`SafetyPolicy`].
///
/// Returns `Ok(())` when `policy.level >= required`, or a [`SafetyViolation`]
/// error when the operation requires a higher level than granted.
///
/// # Parameters
///
/// * `operation` — Human-readable label for the operation being gated.
/// * `required`  — Minimum [`SafetyLevel`] the operation needs.
/// * `policy`    — The [`SafetyPolicy`] held by the caller.
pub fn check_gate(
    operation: &str,
    required: SafetyLevel,
    policy: &SafetyPolicy,
) -> Result<(), SafetyViolation> {
    if policy.level >= required {
        Ok(())
    } else {
        Err(SafetyViolation {
            operation: operation.to_string(),
            required,
            granted: policy.level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SafetyLevel ordering ---

    #[test]
    fn read_only_is_less_than_authorized() {
        assert!(SafetyLevel::ReadOnly < SafetyLevel::Authorized);
    }

    #[test]
    fn read_only_equals_read_only() {
        assert_eq!(SafetyLevel::ReadOnly, SafetyLevel::ReadOnly);
    }

    #[test]
    fn authorized_equals_authorized() {
        assert_eq!(SafetyLevel::Authorized, SafetyLevel::Authorized);
    }

    // --- SafetyLevel::as_str ---

    #[test]
    fn read_only_as_str() {
        assert_eq!(SafetyLevel::ReadOnly.as_str(), "read-only");
    }

    #[test]
    fn authorized_as_str() {
        assert_eq!(SafetyLevel::Authorized.as_str(), "authorized");
    }

    // --- SafetyPolicy constructors ---

    #[test]
    fn read_only_policy_has_read_only_level() {
        assert_eq!(SafetyPolicy::read_only().level, SafetyLevel::ReadOnly);
    }

    #[test]
    fn authorized_policy_has_authorized_level() {
        assert_eq!(SafetyPolicy::authorized().level, SafetyLevel::Authorized);
    }

    #[test]
    fn default_policy_is_read_only() {
        assert_eq!(SafetyPolicy::default().level, SafetyLevel::ReadOnly);
    }

    // --- check_gate: passing cases ---

    #[test]
    fn gate_passes_when_granted_equals_required() {
        let policy = SafetyPolicy::read_only();
        assert!(check_gate("op", SafetyLevel::ReadOnly, &policy).is_ok());
    }

    #[test]
    fn gate_passes_when_granted_exceeds_required() {
        let policy = SafetyPolicy::authorized();
        assert!(check_gate("op", SafetyLevel::ReadOnly, &policy).is_ok());
    }

    #[test]
    fn gate_passes_authorized_when_authorized_granted() {
        let policy = SafetyPolicy::authorized();
        assert!(check_gate("op", SafetyLevel::Authorized, &policy).is_ok());
    }

    // --- check_gate: blocking cases ---

    #[test]
    fn gate_blocks_authorized_when_only_read_only_granted() {
        let policy = SafetyPolicy::read_only();
        let err = check_gate("sessions", SafetyLevel::Authorized, &policy).unwrap_err();
        assert_eq!(err.operation, "sessions");
        assert_eq!(err.required, SafetyLevel::Authorized);
        assert_eq!(err.granted, SafetyLevel::ReadOnly);
    }

    #[test]
    fn violation_display_contains_operation_name() {
        let policy = SafetyPolicy::read_only();
        let err = check_gate("payload-or-protocol", SafetyLevel::Authorized, &policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("payload-or-protocol"), "msg: {msg}");
        assert!(msg.contains("authorized"), "msg: {msg}");
        assert!(msg.contains("read-only"), "msg: {msg}");
    }

    // --- TraceTarget safety levels ---

    #[test]
    fn trace_sessions_requires_authorized() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::Sessions.required_safety_level(), SafetyLevel::Authorized);
    }

    #[test]
    fn trace_payload_requires_authorized() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::PayloadOrProtocol.required_safety_level(), SafetyLevel::Authorized);
    }

    #[test]
    fn trace_processes_is_read_only() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::Processes.required_safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn trace_listeners_and_ports_is_read_only() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::ListenersAndPorts.required_safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn trace_routes_and_interfaces_is_read_only() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::RoutesAndInterfaces.required_safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn trace_logs_is_read_only() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::Logs.required_safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn trace_runtime_dependencies_is_read_only() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::RuntimeDependencies.required_safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn trace_bind_or_transport_anomaly_is_read_only() {
        use crate::trace::TraceTarget;
        assert_eq!(TraceTarget::BindOrTransportAnomaly.required_safety_level(), SafetyLevel::ReadOnly);
    }

    // --- DiscoverScope safety levels ---

    #[test]
    fn discover_repository_is_read_only() {
        use crate::discover::DiscoverScope;
        assert_eq!(DiscoverScope::Repository.required_safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn discover_host_requires_authorized() {
        use crate::discover::DiscoverScope;
        assert_eq!(DiscoverScope::Host.required_safety_level(), SafetyLevel::Authorized);
    }
}
