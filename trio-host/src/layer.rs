//! OSI layer model and status propagation rules for Diagnostic Trio.
//!
//! Findings from Discover, Searcher, and Trace are tagged with an OSI layer so
//! failure surfaces can be isolated systematically.  The layer model also
//! enforces a key invariant: **upper layers cannot be treated as healthy when a
//! lower layer is failed or untested**.
//!
//! # OSI Layers
//!
//! | Value | Name           | Numeric |
//! |-------|----------------|---------|
//! | `L1`  | Physical       | 1       |
//! | `L2`  | Data Link      | 2       |
//! | `L3`  | Network        | 3       |
//! | `L4`  | Transport      | 4       |
//! | `L5`  | Session        | 5       |
//! | `L6`  | Presentation   | 6       |
//! | `L7`  | Application    | 7       |
//!
//! # Lower-layer dependency rule
//!
//! Call [`effective_status`] to apply the rule automatically: if any layer
//! below the queried layer is [`DiagnosticStatus::Fail`] or
//! [`DiagnosticStatus::NotTested`], the effective status of the queried layer
//! is demoted to [`DiagnosticStatus::Blocked`] to prevent a false-healthy
//! reading.

use crate::evidence::DiagnosticStatus;

/// The seven OSI layers, ordered from physical (lowest) to application
/// (highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OsiLayer {
    /// Layer 1 — cables, signals, hardware.
    Physical = 1,
    /// Layer 2 — MAC addressing, Ethernet frames.
    DataLink = 2,
    /// Layer 3 — IP routing and addressing.
    Network = 3,
    /// Layer 4 — end-to-end delivery, TCP/UDP.
    Transport = 4,
    /// Layer 5 — session management and control.
    Session = 5,
    /// Layer 6 — encoding, encryption, compression.
    Presentation = 6,
    /// Layer 7 — application protocols (HTTP, DNS, TLS handshake, …).
    Application = 7,
}

impl OsiLayer {
    /// Canonical numeric layer number (1 – 7).
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Human-readable name of the layer.
    pub fn name(self) -> &'static str {
        match self {
            OsiLayer::Physical => "Physical",
            OsiLayer::DataLink => "Data Link",
            OsiLayer::Network => "Network",
            OsiLayer::Transport => "Transport",
            OsiLayer::Session => "Session",
            OsiLayer::Presentation => "Presentation",
            OsiLayer::Application => "Application",
        }
    }

    /// Try to construct a layer from its numeric value (1 – 7).
    ///
    /// Returns `None` if the value is out of range.
    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            1 => Some(OsiLayer::Physical),
            2 => Some(OsiLayer::DataLink),
            3 => Some(OsiLayer::Network),
            4 => Some(OsiLayer::Transport),
            5 => Some(OsiLayer::Session),
            6 => Some(OsiLayer::Presentation),
            7 => Some(OsiLayer::Application),
            _ => None,
        }
    }

    /// Returns `true` if this layer is strictly below `other` in the OSI stack.
    pub fn is_below(self, other: OsiLayer) -> bool {
        self < other
    }

    /// Returns an iterator over all layers from Physical (L1) up to and
    /// including `self`, ordered lowest first.
    pub fn layers_below_inclusive(self) -> impl Iterator<Item = OsiLayer> {
        ALL_LAYERS.iter().copied().take_while(move |&l| l <= self)
    }
}

/// All OSI layers in ascending order (L1 first).
pub const ALL_LAYERS: [OsiLayer; 7] = [
    OsiLayer::Physical,
    OsiLayer::DataLink,
    OsiLayer::Network,
    OsiLayer::Transport,
    OsiLayer::Session,
    OsiLayer::Presentation,
    OsiLayer::Application,
];

/// Returns `true` if `status` on a lower layer blocks upper layers from being
/// considered healthy.
///
/// [`DiagnosticStatus::Fail`] and [`DiagnosticStatus::NotTested`] both block
/// upper layers.  [`DiagnosticStatus::Blocked`] and
/// [`DiagnosticStatus::Partial`] also propagate a block, because they indicate
/// incomplete or impossible inspection.
pub fn status_blocks_upper(status: &DiagnosticStatus) -> bool {
    matches!(
        status,
        DiagnosticStatus::Fail
            | DiagnosticStatus::NotTested
            | DiagnosticStatus::Blocked
            | DiagnosticStatus::Partial
    )
}

/// Compute the **effective** diagnostic status for `query_layer` given a
/// snapshot of `(layer, status)` pairs from other findings.
///
/// If any layer *below* `query_layer` has a status that blocks upper layers
/// (see [`status_blocks_upper`]), the effective status of `query_layer` is
/// demoted to [`DiagnosticStatus::Blocked`] regardless of what
/// `own_status` says.
///
/// # Parameters
///
/// * `query_layer` — the layer whose effective status is being computed.
/// * `own_status`  — the status that `query_layer`'s own probes reported.
/// * `findings`    — other `(layer, status)` pairs from the current
///   diagnostic session.  May include the query layer itself;
///   those entries are ignored.
pub fn effective_status(
    query_layer: OsiLayer,
    own_status: &DiagnosticStatus,
    findings: &[(OsiLayer, DiagnosticStatus)],
) -> DiagnosticStatus {
    let lower_blocked = findings
        .iter()
        .any(|(l, s)| l.is_below(query_layer) && status_blocks_upper(s));

    if lower_blocked {
        DiagnosticStatus::Blocked
    } else {
        own_status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_numbers_are_correct() {
        assert_eq!(OsiLayer::Physical.number(), 1);
        assert_eq!(OsiLayer::DataLink.number(), 2);
        assert_eq!(OsiLayer::Network.number(), 3);
        assert_eq!(OsiLayer::Transport.number(), 4);
        assert_eq!(OsiLayer::Session.number(), 5);
        assert_eq!(OsiLayer::Presentation.number(), 6);
        assert_eq!(OsiLayer::Application.number(), 7);
    }

    #[test]
    fn layer_names_are_correct() {
        assert_eq!(OsiLayer::Physical.name(), "Physical");
        assert_eq!(OsiLayer::DataLink.name(), "Data Link");
        assert_eq!(OsiLayer::Network.name(), "Network");
        assert_eq!(OsiLayer::Transport.name(), "Transport");
        assert_eq!(OsiLayer::Session.name(), "Session");
        assert_eq!(OsiLayer::Presentation.name(), "Presentation");
        assert_eq!(OsiLayer::Application.name(), "Application");
    }

    #[test]
    fn from_number_round_trips() {
        for n in 1u8..=7 {
            let layer = OsiLayer::from_number(n).expect("valid layer");
            assert_eq!(layer.number(), n);
        }
    }

    #[test]
    fn from_number_rejects_out_of_range() {
        assert!(OsiLayer::from_number(0).is_none());
        assert!(OsiLayer::from_number(8).is_none());
        assert!(OsiLayer::from_number(255).is_none());
    }

    #[test]
    fn ordering_is_ascending() {
        assert!(OsiLayer::Physical < OsiLayer::DataLink);
        assert!(OsiLayer::DataLink < OsiLayer::Network);
        assert!(OsiLayer::Network < OsiLayer::Transport);
        assert!(OsiLayer::Transport < OsiLayer::Session);
        assert!(OsiLayer::Session < OsiLayer::Presentation);
        assert!(OsiLayer::Presentation < OsiLayer::Application);
    }

    #[test]
    fn is_below_works() {
        assert!(OsiLayer::Physical.is_below(OsiLayer::Application));
        assert!(OsiLayer::Network.is_below(OsiLayer::Transport));
        assert!(!OsiLayer::Application.is_below(OsiLayer::Physical));
        assert!(!OsiLayer::Transport.is_below(OsiLayer::Transport));
    }

    #[test]
    fn status_blocks_upper_correctness() {
        assert!(status_blocks_upper(&DiagnosticStatus::Fail));
        assert!(status_blocks_upper(&DiagnosticStatus::NotTested));
        assert!(status_blocks_upper(&DiagnosticStatus::Blocked));
        assert!(status_blocks_upper(&DiagnosticStatus::Partial));
        assert!(!status_blocks_upper(&DiagnosticStatus::Pass));
    }

    #[test]
    fn effective_status_no_lower_findings_passes_through() {
        let result = effective_status(OsiLayer::Application, &DiagnosticStatus::Pass, &[]);
        assert_eq!(result, DiagnosticStatus::Pass);
    }

    #[test]
    fn effective_status_fail_on_lower_layer_blocks_upper() {
        let findings = vec![(OsiLayer::Physical, DiagnosticStatus::Fail)];
        let result = effective_status(OsiLayer::Application, &DiagnosticStatus::Pass, &findings);
        assert_eq!(result, DiagnosticStatus::Blocked);
    }

    #[test]
    fn effective_status_not_tested_on_lower_layer_blocks_upper() {
        let findings = vec![(OsiLayer::Network, DiagnosticStatus::NotTested)];
        let result = effective_status(OsiLayer::Transport, &DiagnosticStatus::Pass, &findings);
        assert_eq!(result, DiagnosticStatus::Blocked);
    }

    #[test]
    fn effective_status_pass_on_lower_layer_allows_upper() {
        let findings = vec![
            (OsiLayer::Physical, DiagnosticStatus::Pass),
            (OsiLayer::DataLink, DiagnosticStatus::Pass),
            (OsiLayer::Network, DiagnosticStatus::Pass),
        ];
        let result = effective_status(OsiLayer::Transport, &DiagnosticStatus::Pass, &findings);
        assert_eq!(result, DiagnosticStatus::Pass);
    }

    #[test]
    fn effective_status_same_layer_findings_ignored() {
        // A Fail finding at the same layer should NOT block itself.
        let findings = vec![(OsiLayer::Application, DiagnosticStatus::Fail)];
        let result = effective_status(OsiLayer::Application, &DiagnosticStatus::Pass, &findings);
        // The query layer's own_status is Pass; same-layer findings are not "lower"
        assert_eq!(result, DiagnosticStatus::Pass);
    }

    #[test]
    fn all_layers_has_seven_entries() {
        assert_eq!(ALL_LAYERS.len(), 7);
    }

    #[test]
    fn layers_below_inclusive_physical_returns_one() {
        let below: Vec<_> = OsiLayer::Physical.layers_below_inclusive().collect();
        assert_eq!(below, vec![OsiLayer::Physical]);
    }

    #[test]
    fn layers_below_inclusive_transport_returns_four() {
        let below: Vec<_> = OsiLayer::Transport.layers_below_inclusive().collect();
        assert_eq!(
            below,
            vec![
                OsiLayer::Physical,
                OsiLayer::DataLink,
                OsiLayer::Network,
                OsiLayer::Transport,
            ]
        );
    }
}
