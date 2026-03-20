//! Diagnostic Trio host execution library.
//!
//! This crate provides the Rust-side execution layer for Diagnostic Trio,
//! responsible for CLI behavior, host interaction, orchestration,
//! normalization, and MCP exposure.

pub mod artifact;
pub mod boundary;
pub mod discover;
pub mod evidence;
pub mod journal;
pub mod layer;
pub mod safety;
pub mod searcher;
pub mod trace;
pub mod workspace;

/// Returns the name and version of the Trio host layer.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!version().is_empty());
    }
}
