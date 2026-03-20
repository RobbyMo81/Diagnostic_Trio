//! Shared workspace and state contract for Diagnostic Trio.
//!
//! Trio tools operate inside a well-known directory tree that provides
//! isolation from the host filesystem and independence from any Quartet
//! internals.  All reads and writes go through the paths defined here so
//! that the layout can be relocated without changing tool behaviour.
//!
//! # Workspace layout
//!
//! ```text
//! <workspace_root>/
//! ├── artifacts/     — durable output files written by Discover, Searcher, Trace
//! ├── cache/         — ephemeral intermediate data that may be evicted freely
//! ├── journal/       — append-only journal entries linking runs to findings
//! └── state/         — mutable shared state exchanged between Trio tools
//! ```
//!
//! # Quartet independence
//!
//! Trio never imports or depends on Quartet crates or modules.  It accesses
//! shared context only through [`SharedState`] values that callers populate
//! before invoking any Trio tool.  Trio writes its results back into the
//! workspace tree; it does not mutate caller-owned data structures.

use std::path::{Path, PathBuf};

/// Canonical sub-directory names inside the workspace root.
pub const ARTIFACTS_DIR: &str = "artifacts";
pub const CACHE_DIR: &str = "cache";
pub const JOURNAL_DIR: &str = "journal";
pub const STATE_DIR: &str = "state";

/// Resolved paths for every logical section of a Trio workspace.
///
/// Construct via [`WorkspaceLayout::new`] and pass the result to Trio tools
/// so they all agree on where to read and write data.
#[derive(Debug, Clone)]
pub struct WorkspaceLayout {
    /// Root directory that contains all workspace sub-directories.
    pub root: PathBuf,
    /// Where Discover, Searcher, and Trace write durable output files.
    pub artifacts: PathBuf,
    /// Where tools may write intermediate data that is safe to delete.
    pub cache: PathBuf,
    /// Where append-only journal entries are stored.
    pub journal: PathBuf,
    /// Where shared state files are exchanged between Trio tools.
    pub state: PathBuf,
}

impl WorkspaceLayout {
    /// Build a [`WorkspaceLayout`] rooted at `root`.
    ///
    /// The root directory need not exist yet; callers are responsible for
    /// creating it before the first tool runs.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            artifacts: root.join(ARTIFACTS_DIR),
            cache: root.join(CACHE_DIR),
            journal: root.join(JOURNAL_DIR),
            state: root.join(STATE_DIR),
            root,
        }
    }

    /// Return the path where a named artifact file should be written.
    ///
    /// For example: `layout.artifact_path("discover-findings.json")`.
    pub fn artifact_path(&self, name: impl AsRef<Path>) -> PathBuf {
        self.artifacts.join(name)
    }

    /// Return the path where a named cache file may be stored.
    pub fn cache_path(&self, name: impl AsRef<Path>) -> PathBuf {
        self.cache.join(name)
    }

    /// Return the path where a named journal file is kept.
    pub fn journal_path(&self, name: impl AsRef<Path>) -> PathBuf {
        self.journal.join(name)
    }

    /// Return the path where a named shared-state file lives.
    pub fn state_path(&self, name: impl AsRef<Path>) -> PathBuf {
        self.state.join(name)
    }
}

/// Context provided to every Trio tool before it runs.
///
/// Each tool reads only the fields it needs; unused fields are ignored.  The
/// struct is intentionally flat — tools must not reach outside it to query
/// Quartet or host state.
///
/// # Tool-specific inputs
///
/// | Tool      | Required fields                                        |
/// |-----------|--------------------------------------------------------|
/// | Discover  | `target`, `workspace`, `discover_scope`                |
/// | Searcher  | `target`, `workspace`, `search_roots`, `search_query`  |
/// | Trace     | `target`, `workspace`, `trace_scope`                   |
#[derive(Debug, Clone)]
pub struct SharedState {
    /// Primary target being diagnosed: a hostname, IP address, service name,
    /// or filesystem path, depending on what the invoking tool expects.
    pub target: String,

    /// Workspace layout that all tools in this run share.
    pub workspace: WorkspaceLayout,

    /// Discover scope: which probe families Discover should execute.
    ///
    /// An empty list means "run all available probes".
    pub discover_scope: Vec<String>,

    /// Filesystem roots Searcher should include in its search.
    ///
    /// Relative paths are resolved against the process working directory.
    pub search_roots: Vec<PathBuf>,

    /// Freeform query or keyword that Searcher uses to filter results.
    pub search_query: Option<String>,

    /// Trace scope: which runtime interrogation targets to inspect.
    ///
    /// An empty list means "inspect all safe targets".  Sensitive targets
    /// must be explicitly named here AND must pass safety gating.
    pub trace_scope: Vec<String>,

    /// Arbitrary key-value metadata forwarded to all tools.
    ///
    /// Use this for probe-specific settings that do not belong in the core
    /// fields above (e.g. port ranges, include/exclude patterns).
    pub extra: std::collections::HashMap<String, String>,
}

impl SharedState {
    /// Construct a minimal [`SharedState`] for a single target.
    pub fn new(target: impl Into<String>, workspace: WorkspaceLayout) -> Self {
        Self {
            target: target.into(),
            workspace,
            discover_scope: Vec::new(),
            search_roots: Vec::new(),
            search_query: None,
            trace_scope: Vec::new(),
            extra: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> WorkspaceLayout {
        WorkspaceLayout::new("/tmp/trio-test-workspace")
    }

    #[test]
    fn workspace_layout_sub_dirs() {
        let l = layout();
        assert_eq!(l.root, PathBuf::from("/tmp/trio-test-workspace"));
        assert_eq!(
            l.artifacts,
            PathBuf::from("/tmp/trio-test-workspace/artifacts")
        );
        assert_eq!(l.cache, PathBuf::from("/tmp/trio-test-workspace/cache"));
        assert_eq!(l.journal, PathBuf::from("/tmp/trio-test-workspace/journal"));
        assert_eq!(l.state, PathBuf::from("/tmp/trio-test-workspace/state"));
    }

    #[test]
    fn artifact_path_helper() {
        let l = layout();
        assert_eq!(
            l.artifact_path("discover-findings.json"),
            PathBuf::from("/tmp/trio-test-workspace/artifacts/discover-findings.json")
        );
    }

    #[test]
    fn cache_path_helper() {
        let l = layout();
        assert_eq!(
            l.cache_path("ripgrep-index"),
            PathBuf::from("/tmp/trio-test-workspace/cache/ripgrep-index")
        );
    }

    #[test]
    fn journal_path_helper() {
        let l = layout();
        assert_eq!(
            l.journal_path("2026-03-19.jsonl"),
            PathBuf::from("/tmp/trio-test-workspace/journal/2026-03-19.jsonl")
        );
    }

    #[test]
    fn state_path_helper() {
        let l = layout();
        assert_eq!(
            l.state_path("shared.json"),
            PathBuf::from("/tmp/trio-test-workspace/state/shared.json")
        );
    }

    #[test]
    fn shared_state_defaults() {
        let state = SharedState::new("example.host", layout());
        assert_eq!(state.target, "example.host");
        assert!(state.discover_scope.is_empty());
        assert!(state.search_roots.is_empty());
        assert!(state.search_query.is_none());
        assert!(state.trace_scope.is_empty());
        assert!(state.extra.is_empty());
    }

    #[test]
    fn shared_state_with_scopes() {
        let mut state = SharedState::new("10.0.0.1", layout());
        state.discover_scope = vec!["config-parse".into(), "dependency-trace".into()];
        state.trace_scope = vec!["processes".into(), "listeners".into()];
        state.search_query = Some("DATABASE_URL".into());
        assert_eq!(state.discover_scope.len(), 2);
        assert_eq!(state.trace_scope.len(), 2);
        assert_eq!(state.search_query.as_deref(), Some("DATABASE_URL"));
    }

    #[test]
    fn workspace_constants_match_layout() {
        let l = layout();
        assert_eq!(l.artifacts.file_name().unwrap(), ARTIFACTS_DIR);
        assert_eq!(l.cache.file_name().unwrap(), CACHE_DIR);
        assert_eq!(l.journal.file_name().unwrap(), JOURNAL_DIR);
        assert_eq!(l.state.file_name().unwrap(), STATE_DIR);
    }
}
