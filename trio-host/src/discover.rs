//! Discover evidence classification for Diagnostic Trio.
//!
//! Discover classifies repository and host evidence into layer-tagged
//! [`EvidenceRecord`] findings using the shared evidence schema.  All
//! Discover evidence is *static* — it derives from files and configuration
//! artifacts without interacting with live processes.
//!
//! # Probe families
//!
//! Each [`DiscoverProbeFamily`] has a default OSI layer assignment:
//!
//! | Probe family       | Default layer             |
//! |--------------------|---------------------------|
//! | `config-parse`     | L7 Application            |
//! | `dependency-trace` | L7 Application            |
//! | `service-config`   | L7 Application            |
//! | `tls-config`       | L6 Presentation           |
//! | `port-config`      | L4 Transport              |
//! | `routing-config`   | L3 Network                |
//! | `host-interface`   | L2 Data Link              |
//!
//! # Scopes
//!
//! [`DiscoverScope::Repository`] covers source code, manifests, and lock
//! files committed to version control.  [`DiscoverScope::Host`] covers
//! OS-level config files present on the running host (e.g.
//! `/etc/resolv.conf`, `/etc/network/interfaces`).  Both produce
//! [`EvidenceKind::Static`] records.

use crate::evidence::{DiagnosticStatus, EvidenceKind, EvidenceRecord};
use crate::layer::OsiLayer;

/// Categories of probes performed by Discover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverProbeFamily {
    /// Parse and validate configuration files.
    ConfigParse,
    /// Trace package manifests and lock files for the dependency surface.
    DependencyTrace,
    /// Examine network-interface configuration (MAC, link state, MTU, …).
    HostInterface,
    /// Inspect IP routing table and addressing configuration.
    RoutingConfig,
    /// Inspect port or socket configuration at the transport layer.
    PortConfig,
    /// Inspect TLS, certificate, or encryption configuration.
    TlsConfig,
    /// Inspect application service definitions and daemon configuration.
    ServiceConfig,
}

impl DiscoverProbeFamily {
    /// Canonical probe-family name used in evidence records.
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoverProbeFamily::ConfigParse => "config-parse",
            DiscoverProbeFamily::DependencyTrace => "dependency-trace",
            DiscoverProbeFamily::HostInterface => "host-interface",
            DiscoverProbeFamily::RoutingConfig => "routing-config",
            DiscoverProbeFamily::PortConfig => "port-config",
            DiscoverProbeFamily::TlsConfig => "tls-config",
            DiscoverProbeFamily::ServiceConfig => "service-config",
        }
    }

    /// Default OSI layer for this probe family.
    pub fn default_layer(&self) -> OsiLayer {
        match self {
            DiscoverProbeFamily::HostInterface => OsiLayer::DataLink,
            DiscoverProbeFamily::RoutingConfig => OsiLayer::Network,
            DiscoverProbeFamily::PortConfig => OsiLayer::Transport,
            DiscoverProbeFamily::TlsConfig => OsiLayer::Presentation,
            DiscoverProbeFamily::ConfigParse
            | DiscoverProbeFamily::DependencyTrace
            | DiscoverProbeFamily::ServiceConfig => OsiLayer::Application,
        }
    }
}

/// Whether the evidence originates from a version-controlled repository or
/// from OS-level artifacts on the running host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverScope {
    /// Source code, manifests, lock files, and committed configuration.
    Repository,
    /// OS-level configuration files present on the running host.
    Host,
}

impl DiscoverScope {
    /// Canonical string label stored in [`EvidenceRecord::metadata`].
    pub fn as_str(self) -> &'static str {
        match self {
            DiscoverScope::Repository => "repository",
            DiscoverScope::Host => "host",
        }
    }
}

/// Classify a static artifact into a layer-tagged Discover evidence record.
///
/// The record is always emitted with `source_tool = "discover"` and
/// `kind = Static`.  The `discover_scope` metadata key records whether the
/// artifact came from the repository or the host filesystem.
///
/// # Parameters
///
/// * `scope`        — [`DiscoverScope::Repository`] or [`DiscoverScope::Host`].
/// * `timestamp`    — RFC 3339 timestamp of when the probe ran.
/// * `target`       — File path, service name, or other artifact identifier.
/// * `probe_family` — The [`DiscoverProbeFamily`] used to examine the target.
/// * `status`       — Outcome of the probe.
/// * `summary`      — Short human-readable finding description.
pub fn classify(
    scope: DiscoverScope,
    timestamp: impl Into<String>,
    target: impl Into<String>,
    probe_family: DiscoverProbeFamily,
    status: DiagnosticStatus,
    summary: impl Into<String>,
) -> EvidenceRecord {
    let layer = probe_family.default_layer();
    let family_str = probe_family.as_str();
    let mut record = EvidenceRecord::new(
        "discover",
        timestamp,
        target,
        family_str,
        status,
        summary,
        EvidenceKind::Static,
    );
    record.layer = Some(layer.number());
    record
        .metadata
        .insert("discover_scope".to_string(), scope.as_str().to_string());
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-03-19T22:00:00Z";

    // --- DiscoverProbeFamily::as_str ---

    #[test]
    fn probe_family_str_config_parse() {
        assert_eq!(DiscoverProbeFamily::ConfigParse.as_str(), "config-parse");
    }

    #[test]
    fn probe_family_str_dependency_trace() {
        assert_eq!(
            DiscoverProbeFamily::DependencyTrace.as_str(),
            "dependency-trace"
        );
    }

    #[test]
    fn probe_family_str_host_interface() {
        assert_eq!(
            DiscoverProbeFamily::HostInterface.as_str(),
            "host-interface"
        );
    }

    #[test]
    fn probe_family_str_routing_config() {
        assert_eq!(
            DiscoverProbeFamily::RoutingConfig.as_str(),
            "routing-config"
        );
    }

    #[test]
    fn probe_family_str_port_config() {
        assert_eq!(DiscoverProbeFamily::PortConfig.as_str(), "port-config");
    }

    #[test]
    fn probe_family_str_tls_config() {
        assert_eq!(DiscoverProbeFamily::TlsConfig.as_str(), "tls-config");
    }

    #[test]
    fn probe_family_str_service_config() {
        assert_eq!(
            DiscoverProbeFamily::ServiceConfig.as_str(),
            "service-config"
        );
    }

    // --- DiscoverProbeFamily::default_layer ---

    #[test]
    fn host_interface_maps_to_l2() {
        assert_eq!(DiscoverProbeFamily::HostInterface.default_layer(), OsiLayer::DataLink);
    }

    #[test]
    fn routing_config_maps_to_l3() {
        assert_eq!(DiscoverProbeFamily::RoutingConfig.default_layer(), OsiLayer::Network);
    }

    #[test]
    fn port_config_maps_to_l4() {
        assert_eq!(DiscoverProbeFamily::PortConfig.default_layer(), OsiLayer::Transport);
    }

    #[test]
    fn tls_config_maps_to_l6() {
        assert_eq!(
            DiscoverProbeFamily::TlsConfig.default_layer(),
            OsiLayer::Presentation
        );
    }

    #[test]
    fn config_parse_maps_to_l7() {
        assert_eq!(
            DiscoverProbeFamily::ConfigParse.default_layer(),
            OsiLayer::Application
        );
    }

    #[test]
    fn dependency_trace_maps_to_l7() {
        assert_eq!(
            DiscoverProbeFamily::DependencyTrace.default_layer(),
            OsiLayer::Application
        );
    }

    #[test]
    fn service_config_maps_to_l7() {
        assert_eq!(
            DiscoverProbeFamily::ServiceConfig.default_layer(),
            OsiLayer::Application
        );
    }

    // --- DiscoverScope ---

    #[test]
    fn scope_as_str() {
        assert_eq!(DiscoverScope::Repository.as_str(), "repository");
        assert_eq!(DiscoverScope::Host.as_str(), "host");
    }

    // --- classify ---

    #[test]
    fn classify_sets_source_tool_to_discover() {
        let rec = classify(
            DiscoverScope::Repository,
            TS,
            "Cargo.toml",
            DiscoverProbeFamily::DependencyTrace,
            DiagnosticStatus::Pass,
            "Lock file present and consistent.",
        );
        assert_eq!(rec.source_tool, "discover");
    }

    #[test]
    fn classify_sets_kind_to_static() {
        let rec = classify(
            DiscoverScope::Host,
            TS,
            "/etc/resolv.conf",
            DiscoverProbeFamily::ConfigParse,
            DiagnosticStatus::Pass,
            "Resolver config present.",
        );
        assert_eq!(rec.kind, EvidenceKind::Static);
    }

    #[test]
    fn classify_assigns_layer_from_probe_family() {
        let rec = classify(
            DiscoverScope::Host,
            TS,
            "/etc/network/interfaces",
            DiscoverProbeFamily::HostInterface,
            DiagnosticStatus::Pass,
            "Interface config found.",
        );
        assert_eq!(rec.layer, Some(OsiLayer::DataLink.number()));
    }

    #[test]
    fn classify_stores_scope_in_metadata_repository() {
        let rec = classify(
            DiscoverScope::Repository,
            TS,
            "pyproject.toml",
            DiscoverProbeFamily::DependencyTrace,
            DiagnosticStatus::Pass,
            "Dependencies pinned.",
        );
        assert_eq!(rec.metadata.get("discover_scope").map(String::as_str), Some("repository"));
    }

    #[test]
    fn classify_stores_scope_in_metadata_host() {
        let rec = classify(
            DiscoverScope::Host,
            TS,
            "/etc/hosts",
            DiscoverProbeFamily::ConfigParse,
            DiagnosticStatus::Pass,
            "Hosts file readable.",
        );
        assert_eq!(rec.metadata.get("discover_scope").map(String::as_str), Some("host"));
    }

    #[test]
    fn classify_records_fail_status() {
        let rec = classify(
            DiscoverScope::Repository,
            TS,
            "requirements.txt",
            DiscoverProbeFamily::DependencyTrace,
            DiagnosticStatus::Fail,
            "Pinned version has known CVE.",
        );
        assert_eq!(rec.status, DiagnosticStatus::Fail);
    }

    #[test]
    fn classify_records_blocked_status() {
        let rec = classify(
            DiscoverScope::Host,
            TS,
            "/etc/shadow",
            DiscoverProbeFamily::ConfigParse,
            DiagnosticStatus::Blocked,
            "Permission denied reading shadow file.",
        );
        assert_eq!(rec.status, DiagnosticStatus::Blocked);
    }

    #[test]
    fn classify_records_partial_status() {
        let rec = classify(
            DiscoverScope::Repository,
            TS,
            "src/",
            DiscoverProbeFamily::ServiceConfig,
            DiagnosticStatus::Partial,
            "Some service configs missing.",
        );
        assert_eq!(rec.status, DiagnosticStatus::Partial);
    }

    #[test]
    fn classify_records_not_tested_status() {
        let rec = classify(
            DiscoverScope::Host,
            TS,
            "/proc/net/route",
            DiscoverProbeFamily::RoutingConfig,
            DiagnosticStatus::NotTested,
            "Route table probe skipped.",
        );
        assert_eq!(rec.status, DiagnosticStatus::NotTested);
    }

    #[test]
    fn classify_tls_config_maps_to_presentation_layer() {
        let rec = classify(
            DiscoverScope::Repository,
            TS,
            "certs/server.pem",
            DiscoverProbeFamily::TlsConfig,
            DiagnosticStatus::Pass,
            "Certificate valid.",
        );
        assert_eq!(rec.layer, Some(6)); // Presentation
    }

    #[test]
    fn classify_routing_maps_to_network_layer() {
        let rec = classify(
            DiscoverScope::Host,
            TS,
            "/etc/iproute2/rt_tables",
            DiscoverProbeFamily::RoutingConfig,
            DiagnosticStatus::Pass,
            "Routing tables found.",
        );
        assert_eq!(rec.layer, Some(3)); // Network
    }
}
