//! Trace runtime evidence capture for Diagnostic Trio.
//!
//! Trace collects live runtime evidence from a running system, capturing
//! behaviour that is invisible to static analysis.  All Trace evidence is
//! [`EvidenceKind::Runtime`] — it requires host access and MUST be gated by
//! safety checks before use.
//!
//! # Interrogation targets and default OSI layers
//!
//! | Target                      | Default layer          |
//! |-----------------------------|------------------------|
//! | `processes`                 | L7 Application         |
//! | `listeners-and-ports`       | L4 Transport           |
//! | `routes-and-interfaces`     | L3 Network             |
//! | `sessions`                  | L5 Session             |
//! | `logs`                      | L7 Application         |
//! | `payload-or-protocol`       | L6 Presentation        |
//! | `runtime-dependencies`      | L7 Application         |
//! | `bind-or-transport-anomaly` | L4 Transport           |
//!
//! # Static vs runtime distinction
//!
//! Unlike Discover (which reads files and manifests), Trace interrogates the
//! live system.  Every [`capture`] call produces an [`EvidenceRecord`] with
//! `kind = Runtime`, and the `trace_target` metadata key records which
//! interrogation target was used.

use crate::evidence::{DiagnosticStatus, EvidenceKind, EvidenceRecord};
use crate::layer::OsiLayer;
use crate::safety::SafetyLevel;

/// Runtime interrogation targets supported by Trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceTarget {
    /// Enumerate running processes and their attributes.
    Processes,
    /// Inspect active listeners and open network ports.
    ListenersAndPorts,
    /// Inspect live IP routes and network interface state.
    RoutesAndInterfaces,
    /// Inspect active sessions (TCP established, SSH, TLS handshake state, …).
    Sessions,
    /// Read live or recently-rotated log streams.
    Logs,
    /// Observe payload or protocol-level behaviour (headers, framing, codec).
    PayloadOrProtocol,
    /// Probe runtime dependency availability (DNS resolution, reach, latency).
    RuntimeDependencies,
    /// Detect bind failures, port conflicts, or transport-level anomalies.
    BindOrTransportAnomaly,
}

impl TraceTarget {
    /// Canonical probe-family name stored in evidence records.
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceTarget::Processes => "processes",
            TraceTarget::ListenersAndPorts => "listeners-and-ports",
            TraceTarget::RoutesAndInterfaces => "routes-and-interfaces",
            TraceTarget::Sessions => "sessions",
            TraceTarget::Logs => "logs",
            TraceTarget::PayloadOrProtocol => "payload-or-protocol",
            TraceTarget::RuntimeDependencies => "runtime-dependencies",
            TraceTarget::BindOrTransportAnomaly => "bind-or-transport-anomaly",
        }
    }

    /// Minimum [`SafetyLevel`] required to run this interrogation target.
    ///
    /// Most targets are `ReadOnly` (passive observation).  `Sessions` and
    /// `PayloadOrProtocol` require `Authorized` because they observe privileged
    /// state (session credentials, packet payload content).
    pub fn required_safety_level(&self) -> SafetyLevel {
        match self {
            TraceTarget::Sessions | TraceTarget::PayloadOrProtocol => SafetyLevel::Authorized,
            _ => SafetyLevel::ReadOnly,
        }
    }

    /// Default OSI layer for findings from this interrogation target.
    pub fn default_layer(&self) -> OsiLayer {
        match self {
            TraceTarget::RoutesAndInterfaces => OsiLayer::Network,
            TraceTarget::Sessions => OsiLayer::Session,
            TraceTarget::PayloadOrProtocol => OsiLayer::Presentation,
            TraceTarget::ListenersAndPorts | TraceTarget::BindOrTransportAnomaly => {
                OsiLayer::Transport
            }
            TraceTarget::Processes
            | TraceTarget::Logs
            | TraceTarget::RuntimeDependencies => OsiLayer::Application,
        }
    }
}

/// Capture a runtime observation as a layer-tagged Trace evidence record.
///
/// The record is always emitted with `source_tool = "trace"` and
/// `kind = Runtime`.  The `trace_target` metadata key records which
/// interrogation target was used.
///
/// # Parameters
///
/// * `timestamp`  — RFC 3339 timestamp of when the probe ran.
/// * `target`     — Process name, interface, port, log path, or other identifier.
/// * `trace_tgt`  — The [`TraceTarget`] used to interrogate the system.
/// * `status`     — Outcome of the probe.
/// * `summary`    — Short human-readable finding description.
pub fn capture(
    timestamp: impl Into<String>,
    target: impl Into<String>,
    trace_tgt: TraceTarget,
    status: DiagnosticStatus,
    summary: impl Into<String>,
) -> EvidenceRecord {
    let layer = trace_tgt.default_layer();
    let family_str = trace_tgt.as_str();
    let mut record = EvidenceRecord::new(
        "trace",
        timestamp,
        target,
        family_str,
        status,
        summary,
        EvidenceKind::Runtime,
    );
    record.layer = Some(layer.number());
    record
        .metadata
        .insert("trace_target".to_string(), family_str.to_string());
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-03-19T23:00:00Z";

    // --- TraceTarget::as_str ---

    #[test]
    fn target_str_processes() {
        assert_eq!(TraceTarget::Processes.as_str(), "processes");
    }

    #[test]
    fn target_str_listeners_and_ports() {
        assert_eq!(TraceTarget::ListenersAndPorts.as_str(), "listeners-and-ports");
    }

    #[test]
    fn target_str_routes_and_interfaces() {
        assert_eq!(TraceTarget::RoutesAndInterfaces.as_str(), "routes-and-interfaces");
    }

    #[test]
    fn target_str_sessions() {
        assert_eq!(TraceTarget::Sessions.as_str(), "sessions");
    }

    #[test]
    fn target_str_logs() {
        assert_eq!(TraceTarget::Logs.as_str(), "logs");
    }

    #[test]
    fn target_str_payload_or_protocol() {
        assert_eq!(TraceTarget::PayloadOrProtocol.as_str(), "payload-or-protocol");
    }

    #[test]
    fn target_str_runtime_dependencies() {
        assert_eq!(TraceTarget::RuntimeDependencies.as_str(), "runtime-dependencies");
    }

    #[test]
    fn target_str_bind_or_transport_anomaly() {
        assert_eq!(TraceTarget::BindOrTransportAnomaly.as_str(), "bind-or-transport-anomaly");
    }

    // --- TraceTarget::default_layer ---

    #[test]
    fn processes_maps_to_l7() {
        assert_eq!(TraceTarget::Processes.default_layer(), OsiLayer::Application);
    }

    #[test]
    fn listeners_and_ports_maps_to_l4() {
        assert_eq!(TraceTarget::ListenersAndPorts.default_layer(), OsiLayer::Transport);
    }

    #[test]
    fn routes_and_interfaces_maps_to_l3() {
        assert_eq!(TraceTarget::RoutesAndInterfaces.default_layer(), OsiLayer::Network);
    }

    #[test]
    fn sessions_maps_to_l5() {
        assert_eq!(TraceTarget::Sessions.default_layer(), OsiLayer::Session);
    }

    #[test]
    fn logs_maps_to_l7() {
        assert_eq!(TraceTarget::Logs.default_layer(), OsiLayer::Application);
    }

    #[test]
    fn payload_or_protocol_maps_to_l6() {
        assert_eq!(TraceTarget::PayloadOrProtocol.default_layer(), OsiLayer::Presentation);
    }

    #[test]
    fn runtime_dependencies_maps_to_l7() {
        assert_eq!(TraceTarget::RuntimeDependencies.default_layer(), OsiLayer::Application);
    }

    #[test]
    fn bind_or_transport_anomaly_maps_to_l4() {
        assert_eq!(TraceTarget::BindOrTransportAnomaly.default_layer(), OsiLayer::Transport);
    }

    // --- capture ---

    #[test]
    fn capture_sets_source_tool_to_trace() {
        let rec = capture(TS, "nginx", TraceTarget::Processes, DiagnosticStatus::Pass, "Running.");
        assert_eq!(rec.source_tool, "trace");
    }

    #[test]
    fn capture_sets_kind_to_runtime() {
        let rec = capture(TS, "nginx", TraceTarget::Processes, DiagnosticStatus::Pass, "Running.");
        assert_eq!(rec.kind, EvidenceKind::Runtime);
    }

    #[test]
    fn capture_assigns_layer_from_target() {
        let rec = capture(TS, ":443", TraceTarget::ListenersAndPorts, DiagnosticStatus::Pass, "Listening.");
        assert_eq!(rec.layer, Some(OsiLayer::Transport.number())); // L4
    }

    #[test]
    fn capture_stores_trace_target_in_metadata() {
        let rec = capture(TS, "eth0", TraceTarget::RoutesAndInterfaces, DiagnosticStatus::Pass, "Route OK.");
        assert_eq!(rec.metadata.get("trace_target").map(String::as_str), Some("routes-and-interfaces"));
    }

    #[test]
    fn capture_sessions_maps_to_l5() {
        let rec = capture(TS, "ssh", TraceTarget::Sessions, DiagnosticStatus::Pass, "Session active.");
        assert_eq!(rec.layer, Some(5)); // Session
    }

    #[test]
    fn capture_payload_maps_to_l6() {
        let rec = capture(TS, "http", TraceTarget::PayloadOrProtocol, DiagnosticStatus::Fail, "Bad framing.");
        assert_eq!(rec.layer, Some(6)); // Presentation
    }

    #[test]
    fn capture_records_fail_status() {
        let rec = capture(TS, ":8080", TraceTarget::BindOrTransportAnomaly, DiagnosticStatus::Fail, "Port in use.");
        assert_eq!(rec.status, DiagnosticStatus::Fail);
    }

    #[test]
    fn capture_records_blocked_status() {
        let rec = capture(TS, "/var/log/secure", TraceTarget::Logs, DiagnosticStatus::Blocked, "Permission denied.");
        assert_eq!(rec.status, DiagnosticStatus::Blocked);
    }

    #[test]
    fn capture_records_partial_status() {
        let rec = capture(TS, "dns", TraceTarget::RuntimeDependencies, DiagnosticStatus::Partial, "Some resolvers unreachable.");
        assert_eq!(rec.status, DiagnosticStatus::Partial);
    }

    #[test]
    fn capture_records_not_tested_status() {
        let rec = capture(TS, "lo", TraceTarget::RoutesAndInterfaces, DiagnosticStatus::NotTested, "Loopback skipped.");
        assert_eq!(rec.status, DiagnosticStatus::NotTested);
    }
}
