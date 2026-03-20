//! Searcher backend catalog and result normalization for Diagnostic Trio.
//!
//! Searcher knows which search tools are available on the host, what each
//! tool can do, and which are preferred versus optional fallbacks.  This
//! catalog is the authoritative source of truth for capability selection and
//! graceful-degradation logic.
//!
//! # Backend categories
//!
//! | Category              | Examples                              |
//! |-----------------------|---------------------------------------|
//! | `HighPerformance`     | `rg` (ripgrep), `ag`, `ugrep`        |
//! | `Specialized`         | `fd`, `jq`, `yq`                     |
//! | `WindowsCompatible`   | `findstr`, `Select-String`           |
//! | `OptionalInteractive` | `fzf`, `peco`                        |
//! | `TextProcessing`      | `grep`, `awk`, `sed`                 |
//!
//! # Preferred vs. fallback
//!
//! Backends with `preferred = true` are selected first when multiple tools
//! can satisfy a search intent.  Backends with `preferred = false` are used
//! only when no preferred backend for the same category is available.
//! Searcher always preserves the normalised output shape regardless of which
//! backend runs.
//!
//! # Result normalisation
//!
//! Raw search hits are normalised into [`crate::evidence::EvidenceRecord`]
//! values via [`normalize`].  Each hit carries a [`SearchIntent`] describing
//! *why* the search was issued and a [`ResultKind`] describing the type of
//! artifact that matched.  The normaliser uses the intent to assign a default
//! OSI layer and to populate the `probe_family` field.

use std::collections::HashMap;

use crate::evidence::{DiagnosticStatus, EvidenceKind, EvidenceRecord};

// ── Search intent ────────────────────────────────────────────────────────────

/// Why a search was issued — used to assign probe family and default OSI layer.
///
/// | Intent                        | Default layer | Probe family label              |
/// |-------------------------------|---------------|---------------------------------|
/// | `ConfigLookup`                | 7 Application | `"config-lookup"`               |
/// | `ErrorStringHunt`             | 7 Application | `"error-string-hunt"`           |
/// | `EntryPointTracing`           | 7 Application | `"entry-point-tracing"`         |
/// | `DependencyTracing`           | 7 Application | `"dependency-tracing"`          |
/// | `SchemaOrPayloadSearch`       | 6 Presentation| `"schema-or-payload-search"`    |
/// | `SecretOrConfigSurface`       | 7 Application | `"secret-or-config-surface"`    |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchIntent {
    /// Locate configuration values, keys, or files for a target component.
    ConfigLookup,
    /// Hunt for error strings, stack traces, or exception patterns.
    ErrorStringHunt,
    /// Trace entry points such as `main`, CLI handlers, or route registrations.
    EntryPointTracing,
    /// Trace imports, `require`, `use`, or manifest dependency declarations.
    DependencyTracing,
    /// Search data schemas, serialisation formats, or protocol payloads.
    SchemaOrPayloadSearch,
    /// Surface exposed secrets, credentials, or sensitive config values.
    SecretOrConfigSurfaceDetection,
}

impl SearchIntent {
    /// Canonical lowercase label used in `probe_family`.
    pub fn as_str(self) -> &'static str {
        match self {
            SearchIntent::ConfigLookup => "config-lookup",
            SearchIntent::ErrorStringHunt => "error-string-hunt",
            SearchIntent::EntryPointTracing => "entry-point-tracing",
            SearchIntent::DependencyTracing => "dependency-tracing",
            SearchIntent::SchemaOrPayloadSearch => "schema-or-payload-search",
            SearchIntent::SecretOrConfigSurfaceDetection => "secret-or-config-surface",
        }
    }

    /// Default OSI layer for findings produced by this intent.
    ///
    /// Returns `None` when the intent does not map to a single well-known layer.
    pub fn default_layer(self) -> Option<u8> {
        match self {
            SearchIntent::SchemaOrPayloadSearch => Some(6), // Presentation
            _ => Some(7),                                   // Application
        }
    }
}

// ── Result kind ──────────────────────────────────────────────────────────────

/// The type of artifact that matched a search query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    /// A generic file path match (name or path search, no content examined).
    File,
    /// A configuration file or embedded config value.
    Config,
    /// A log file or log-formatted text stream.
    Log,
    /// Application source code.
    SourceCode,
    /// Structured-text format: JSON, YAML, TOML, XML, CSV, …
    StructuredText,
    /// Machine-generated artifact: build output, lock file, schema dump, …
    GeneratedArtifact,
}

impl ResultKind {
    /// Canonical lowercase label stored in evidence metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ResultKind::File => "file",
            ResultKind::Config => "config",
            ResultKind::Log => "log",
            ResultKind::SourceCode => "source-code",
            ResultKind::StructuredText => "structured-text",
            ResultKind::GeneratedArtifact => "generated-artifact",
        }
    }
}

// ── Raw search hit ───────────────────────────────────────────────────────────

/// Unprocessed output from a single search backend match, ready for
/// normalisation into an [`EvidenceRecord`].
#[derive(Debug, Clone)]
pub struct RawSearchHit {
    /// Path to the file that contained the match.
    pub file_path: String,
    /// Line number of the match, if the backend reports it.
    pub line_number: Option<u32>,
    /// The matched text or excerpt returned by the backend.
    pub matched_text: String,
    /// Name of the backend that produced this hit (e.g. `"rg"`).
    pub backend: String,
    /// Why the search was issued.
    pub intent: SearchIntent,
    /// Type of artifact that matched.
    pub result_kind: ResultKind,
    /// The query string or pattern that was searched.
    pub query: String,
}

// ── Normalisation ────────────────────────────────────────────────────────────

/// Normalise a raw search hit into a shared [`EvidenceRecord`].
///
/// # Arguments
///
/// * `hit` — the raw match from a search backend.
/// * `timestamp` — RFC 3339 timestamp of when the search ran.
/// * `status` — caller-assigned diagnostic status (e.g. [`DiagnosticStatus::Pass`]
///   when a config was found, [`DiagnosticStatus::Fail`] when a secret is exposed).
///
/// The record's `source_tool` is always `"searcher"`, `probe_family` is taken
/// from [`SearchIntent::as_str`], and `layer` from [`SearchIntent::default_layer`].
/// The `kind` is always [`EvidenceKind::Static`] — Searcher operates on
/// repository and filesystem artifacts, never on live runtime state.
pub fn normalize(hit: &RawSearchHit, timestamp: &str, status: DiagnosticStatus) -> EvidenceRecord {
    let summary = format!(
        "[{}] query {:?} matched in {}{}",
        hit.intent.as_str(),
        hit.query,
        hit.file_path,
        hit.line_number
            .map(|n| format!(":{n}"))
            .unwrap_or_default(),
    );

    let mut raw_refs = vec![hit.matched_text.clone()];
    if let Some(ln) = hit.line_number {
        raw_refs.push(format!("{}:{}", hit.file_path, ln));
    }

    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("backend".into(), hit.backend.clone());
    metadata.insert("result_kind".into(), hit.result_kind.as_str().into());
    metadata.insert("query".into(), hit.query.clone());
    if let Some(ln) = hit.line_number {
        metadata.insert("line_number".into(), ln.to_string());
    }

    EvidenceRecord {
        source_tool: "searcher".into(),
        timestamp: timestamp.into(),
        target: hit.file_path.clone(),
        probe_family: hit.intent.as_str().into(),
        layer: hit.intent.default_layer(),
        status,
        summary,
        kind: EvidenceKind::Static,
        raw_refs,
        confidence: 1.0,
        interpretation: None,
        metadata,
    }
}

// ── Backend catalog ──────────────────────────────────────────────────────────

/// Broad category that determines how a backend is grouped and selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendCategory {
    /// Fast, purpose-built search engines designed for recursive code search.
    HighPerformance,
    /// Tools optimised for a specific file type, format, or search style.
    Specialized,
    /// Search tools that work on Windows without POSIX dependencies.
    WindowsCompatible,
    /// Interactive selection filters; useful but not required for automation.
    OptionalInteractive,
    /// Classic POSIX text-processing utilities used as last-resort fallbacks.
    TextProcessing,
}

impl BackendCategory {
    /// Canonical lowercase category label.
    pub fn as_str(self) -> &'static str {
        match self {
            BackendCategory::HighPerformance => "high-performance",
            BackendCategory::Specialized => "specialized",
            BackendCategory::WindowsCompatible => "windows-compatible",
            BackendCategory::OptionalInteractive => "optional-interactive",
            BackendCategory::TextProcessing => "text-processing",
        }
    }
}

/// Individual capability flags a backend may support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendCapability {
    /// Searches directories recursively without extra flags.
    RecursiveSearch,
    /// Supports full regular-expression patterns.
    RegexSearch,
    /// Respects `.gitignore` and similar ignore files by default.
    GitAware,
    /// Can search inside binary files.
    BinarySearch,
    /// Supports patterns that span multiple lines.
    MultilineSearch,
    /// Queries structured data formats (JSON, YAML, TOML, …).
    StructuredQuery,
    /// Provides an interactive fuzzy-selection UI.
    InteractiveFilter,
    /// Finds files by name / path pattern (not content).
    FileSearch,
    /// Processes text streams line-by-line (awk / sed style).
    StreamProcessing,
}

impl BackendCapability {
    /// Canonical lowercase capability label.
    pub fn as_str(self) -> &'static str {
        match self {
            BackendCapability::RecursiveSearch => "recursive-search",
            BackendCapability::RegexSearch => "regex-search",
            BackendCapability::GitAware => "git-aware",
            BackendCapability::BinarySearch => "binary-search",
            BackendCapability::MultilineSearch => "multiline-search",
            BackendCapability::StructuredQuery => "structured-query",
            BackendCapability::InteractiveFilter => "interactive-filter",
            BackendCapability::FileSearch => "file-search",
            BackendCapability::StreamProcessing => "stream-processing",
        }
    }
}

/// Normalised descriptor for a single Searcher backend.
///
/// All fields are `'static` so the catalog can live as a compile-time
/// constant slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchBackend {
    /// Canonical command name used to invoke the tool (e.g. `"rg"`).
    pub name: &'static str,
    /// Human-readable label for display and logging.
    pub label: &'static str,
    /// Broad category that governs selection and fallback priority.
    pub category: BackendCategory,
    /// `true` when this backend is the first choice for its category;
    /// `false` when it should only be used if no preferred backend is found.
    pub preferred: bool,
    /// Capabilities this backend exposes to Searcher consumers.
    pub capabilities: &'static [BackendCapability],
}

impl SearchBackend {
    /// Returns `true` if the backend supports the given capability.
    pub fn has_capability(&self, cap: BackendCapability) -> bool {
        self.capabilities.contains(&cap)
    }
}

/// The complete Searcher backend catalog.
///
/// Entries are ordered by priority within each category: preferred backends
/// appear before optional fallbacks.  Callers SHOULD iterate the slice in
/// order when selecting a backend for a given capability.
pub static CATALOG: &[SearchBackend] = &[
    // ── High-performance ────────────────────────────────────────────────────
    SearchBackend {
        name: "rg",
        label: "ripgrep",
        category: BackendCategory::HighPerformance,
        preferred: true,
        capabilities: &[
            BackendCapability::RecursiveSearch,
            BackendCapability::RegexSearch,
            BackendCapability::GitAware,
            BackendCapability::BinarySearch,
            BackendCapability::MultilineSearch,
        ],
    },
    SearchBackend {
        name: "ag",
        label: "The Silver Searcher",
        category: BackendCategory::HighPerformance,
        preferred: true,
        capabilities: &[
            BackendCapability::RecursiveSearch,
            BackendCapability::RegexSearch,
            BackendCapability::GitAware,
        ],
    },
    SearchBackend {
        name: "ugrep",
        label: "ugrep",
        category: BackendCategory::HighPerformance,
        preferred: false,
        capabilities: &[
            BackendCapability::RecursiveSearch,
            BackendCapability::RegexSearch,
            BackendCapability::BinarySearch,
            BackendCapability::StructuredQuery,
        ],
    },
    // ── Specialized ─────────────────────────────────────────────────────────
    SearchBackend {
        name: "fd",
        label: "fd",
        category: BackendCategory::Specialized,
        preferred: true,
        capabilities: &[
            BackendCapability::RecursiveSearch,
            BackendCapability::FileSearch,
            BackendCapability::GitAware,
        ],
    },
    SearchBackend {
        name: "jq",
        label: "jq",
        category: BackendCategory::Specialized,
        preferred: true,
        capabilities: &[BackendCapability::StructuredQuery],
    },
    SearchBackend {
        name: "yq",
        label: "yq",
        category: BackendCategory::Specialized,
        preferred: true,
        capabilities: &[BackendCapability::StructuredQuery],
    },
    // ── Windows-compatible ──────────────────────────────────────────────────
    SearchBackend {
        name: "findstr",
        label: "findstr",
        category: BackendCategory::WindowsCompatible,
        preferred: true,
        capabilities: &[
            BackendCapability::RecursiveSearch,
            BackendCapability::RegexSearch,
        ],
    },
    SearchBackend {
        name: "Select-String",
        label: "PowerShell Select-String",
        category: BackendCategory::WindowsCompatible,
        preferred: true,
        capabilities: &[
            BackendCapability::RegexSearch,
            BackendCapability::MultilineSearch,
        ],
    },
    // ── Optional interactive ─────────────────────────────────────────────────
    SearchBackend {
        name: "fzf",
        label: "fzf",
        category: BackendCategory::OptionalInteractive,
        preferred: true,
        capabilities: &[BackendCapability::InteractiveFilter],
    },
    SearchBackend {
        name: "peco",
        label: "peco",
        category: BackendCategory::OptionalInteractive,
        preferred: false,
        capabilities: &[BackendCapability::InteractiveFilter],
    },
    // ── Text processing (last-resort fallbacks) ──────────────────────────────
    SearchBackend {
        name: "grep",
        label: "GNU grep",
        category: BackendCategory::TextProcessing,
        preferred: false,
        capabilities: &[
            BackendCapability::RecursiveSearch,
            BackendCapability::RegexSearch,
            BackendCapability::BinarySearch,
        ],
    },
    SearchBackend {
        name: "awk",
        label: "awk",
        category: BackendCategory::TextProcessing,
        preferred: false,
        capabilities: &[BackendCapability::StreamProcessing],
    },
    SearchBackend {
        name: "sed",
        label: "sed",
        category: BackendCategory::TextProcessing,
        preferred: false,
        capabilities: &[BackendCapability::StreamProcessing],
    },
];

/// Return all backends in `CATALOG` that have the requested capability,
/// preferred backends first.
pub fn backends_with_capability(cap: BackendCapability) -> Vec<&'static SearchBackend> {
    let mut results: Vec<&SearchBackend> = CATALOG
        .iter()
        .filter(|b| b.has_capability(cap))
        .collect();
    // Stable sort: preferred before non-preferred, original order preserved
    // within each tier.
    results.sort_by_key(|b| !b.preferred);
    results
}

/// Select the best available backend for the given capability.
///
/// Iterates [`backends_with_capability`] (preferred-first order) and returns
/// the first entry whose `name` appears in `available`.  Returns `None` when
/// no capable backend is installed on the host.
///
/// # Arguments
///
/// * `cap` — the capability that the chosen backend must support.
/// * `available` — names of backends present on the host (e.g. `["rg", "grep"]`).
///
/// # Fallback guarantee
///
/// Because [`backends_with_capability`] sorts preferred before non-preferred,
/// this function automatically degrades to a fallback backend when a preferred
/// tool is absent.  Callers do not need to inspect the `preferred` flag —
/// they always receive the best available option.
pub fn select_backend<'a>(
    cap: BackendCapability,
    available: &[&str],
) -> Option<&'static SearchBackend> {
    backends_with_capability(cap)
        .into_iter()
        .find(|b| available.contains(&b.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── BackendCategory::as_str ──────────────────────────────────────────────

    #[test]
    fn category_str_high_performance() {
        assert_eq!(BackendCategory::HighPerformance.as_str(), "high-performance");
    }

    #[test]
    fn category_str_specialized() {
        assert_eq!(BackendCategory::Specialized.as_str(), "specialized");
    }

    #[test]
    fn category_str_windows_compatible() {
        assert_eq!(
            BackendCategory::WindowsCompatible.as_str(),
            "windows-compatible"
        );
    }

    #[test]
    fn category_str_optional_interactive() {
        assert_eq!(
            BackendCategory::OptionalInteractive.as_str(),
            "optional-interactive"
        );
    }

    #[test]
    fn category_str_text_processing() {
        assert_eq!(BackendCategory::TextProcessing.as_str(), "text-processing");
    }

    // ── BackendCapability::as_str ────────────────────────────────────────────

    #[test]
    fn capability_str_recursive() {
        assert_eq!(
            BackendCapability::RecursiveSearch.as_str(),
            "recursive-search"
        );
    }

    #[test]
    fn capability_str_regex() {
        assert_eq!(BackendCapability::RegexSearch.as_str(), "regex-search");
    }

    #[test]
    fn capability_str_git_aware() {
        assert_eq!(BackendCapability::GitAware.as_str(), "git-aware");
    }

    // ── Catalog completeness ─────────────────────────────────────────────────

    #[test]
    fn catalog_is_non_empty() {
        assert!(!CATALOG.is_empty());
    }

    #[test]
    fn catalog_contains_rg() {
        assert!(CATALOG.iter().any(|b| b.name == "rg"));
    }

    #[test]
    fn catalog_contains_ag() {
        assert!(CATALOG.iter().any(|b| b.name == "ag"));
    }

    #[test]
    fn catalog_contains_fd() {
        assert!(CATALOG.iter().any(|b| b.name == "fd"));
    }

    #[test]
    fn catalog_contains_jq() {
        assert!(CATALOG.iter().any(|b| b.name == "jq"));
    }

    #[test]
    fn catalog_contains_yq() {
        assert!(CATALOG.iter().any(|b| b.name == "yq"));
    }

    #[test]
    fn catalog_contains_findstr() {
        assert!(CATALOG.iter().any(|b| b.name == "findstr"));
    }

    #[test]
    fn catalog_contains_select_string() {
        assert!(CATALOG.iter().any(|b| b.name == "Select-String"));
    }

    #[test]
    fn catalog_contains_fzf() {
        assert!(CATALOG.iter().any(|b| b.name == "fzf"));
    }

    #[test]
    fn catalog_contains_grep() {
        assert!(CATALOG.iter().any(|b| b.name == "grep"));
    }

    // ── Preferred vs. fallback ───────────────────────────────────────────────

    #[test]
    fn rg_is_preferred() {
        let rg = CATALOG.iter().find(|b| b.name == "rg").unwrap();
        assert!(rg.preferred);
    }

    #[test]
    fn grep_is_not_preferred() {
        let grep = CATALOG.iter().find(|b| b.name == "grep").unwrap();
        assert!(!grep.preferred);
    }

    #[test]
    fn ugrep_is_not_preferred() {
        let ugrep = CATALOG.iter().find(|b| b.name == "ugrep").unwrap();
        assert!(!ugrep.preferred);
    }

    // ── has_capability ───────────────────────────────────────────────────────

    #[test]
    fn rg_has_git_aware() {
        let rg = CATALOG.iter().find(|b| b.name == "rg").unwrap();
        assert!(rg.has_capability(BackendCapability::GitAware));
    }

    #[test]
    fn grep_lacks_git_aware() {
        let grep = CATALOG.iter().find(|b| b.name == "grep").unwrap();
        assert!(!grep.has_capability(BackendCapability::GitAware));
    }

    #[test]
    fn jq_has_structured_query() {
        let jq = CATALOG.iter().find(|b| b.name == "jq").unwrap();
        assert!(jq.has_capability(BackendCapability::StructuredQuery));
    }

    #[test]
    fn fzf_has_interactive_filter() {
        let fzf = CATALOG.iter().find(|b| b.name == "fzf").unwrap();
        assert!(fzf.has_capability(BackendCapability::InteractiveFilter));
    }

    // ── backends_with_capability ─────────────────────────────────────────────

    #[test]
    fn recursive_search_returns_rg_first() {
        let results = backends_with_capability(BackendCapability::RecursiveSearch);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "rg");
    }

    #[test]
    fn structured_query_includes_jq_and_yq() {
        let names: Vec<&str> = backends_with_capability(BackendCapability::StructuredQuery)
            .iter()
            .map(|b| b.name)
            .collect();
        assert!(names.contains(&"jq"));
        assert!(names.contains(&"yq"));
    }

    #[test]
    fn interactive_filter_returns_fzf_before_peco() {
        let results = backends_with_capability(BackendCapability::InteractiveFilter);
        let fzf_idx = results.iter().position(|b| b.name == "fzf").unwrap();
        let peco_idx = results.iter().position(|b| b.name == "peco").unwrap();
        assert!(fzf_idx < peco_idx);
    }

    // ── Category membership ──────────────────────────────────────────────────

    #[test]
    fn rg_category_is_high_performance() {
        let rg = CATALOG.iter().find(|b| b.name == "rg").unwrap();
        assert_eq!(rg.category, BackendCategory::HighPerformance);
    }

    #[test]
    fn fd_category_is_specialized() {
        let fd = CATALOG.iter().find(|b| b.name == "fd").unwrap();
        assert_eq!(fd.category, BackendCategory::Specialized);
    }

    #[test]
    fn findstr_category_is_windows_compatible() {
        let findstr = CATALOG.iter().find(|b| b.name == "findstr").unwrap();
        assert_eq!(findstr.category, BackendCategory::WindowsCompatible);
    }

    #[test]
    fn fzf_category_is_optional_interactive() {
        let fzf = CATALOG.iter().find(|b| b.name == "fzf").unwrap();
        assert_eq!(fzf.category, BackendCategory::OptionalInteractive);
    }

    #[test]
    fn grep_category_is_text_processing() {
        let grep = CATALOG.iter().find(|b| b.name == "grep").unwrap();
        assert_eq!(grep.category, BackendCategory::TextProcessing);
    }

    // ── SearchIntent::as_str ─────────────────────────────────────────────────

    #[test]
    fn intent_str_config_lookup() {
        assert_eq!(SearchIntent::ConfigLookup.as_str(), "config-lookup");
    }

    #[test]
    fn intent_str_error_string_hunt() {
        assert_eq!(SearchIntent::ErrorStringHunt.as_str(), "error-string-hunt");
    }

    #[test]
    fn intent_str_entry_point_tracing() {
        assert_eq!(
            SearchIntent::EntryPointTracing.as_str(),
            "entry-point-tracing"
        );
    }

    #[test]
    fn intent_str_dependency_tracing() {
        assert_eq!(
            SearchIntent::DependencyTracing.as_str(),
            "dependency-tracing"
        );
    }

    #[test]
    fn intent_str_schema_or_payload_search() {
        assert_eq!(
            SearchIntent::SchemaOrPayloadSearch.as_str(),
            "schema-or-payload-search"
        );
    }

    #[test]
    fn intent_str_secret_surface() {
        assert_eq!(
            SearchIntent::SecretOrConfigSurfaceDetection.as_str(),
            "secret-or-config-surface"
        );
    }

    // ── SearchIntent::default_layer ──────────────────────────────────────────

    #[test]
    fn config_lookup_maps_to_layer_7() {
        assert_eq!(SearchIntent::ConfigLookup.default_layer(), Some(7));
    }

    #[test]
    fn schema_or_payload_maps_to_layer_6() {
        assert_eq!(SearchIntent::SchemaOrPayloadSearch.default_layer(), Some(6));
    }

    #[test]
    fn dependency_tracing_maps_to_layer_7() {
        assert_eq!(SearchIntent::DependencyTracing.default_layer(), Some(7));
    }

    // ── ResultKind::as_str ───────────────────────────────────────────────────

    #[test]
    fn result_kind_file() {
        assert_eq!(ResultKind::File.as_str(), "file");
    }

    #[test]
    fn result_kind_config() {
        assert_eq!(ResultKind::Config.as_str(), "config");
    }

    #[test]
    fn result_kind_log() {
        assert_eq!(ResultKind::Log.as_str(), "log");
    }

    #[test]
    fn result_kind_source_code() {
        assert_eq!(ResultKind::SourceCode.as_str(), "source-code");
    }

    #[test]
    fn result_kind_structured_text() {
        assert_eq!(ResultKind::StructuredText.as_str(), "structured-text");
    }

    #[test]
    fn result_kind_generated_artifact() {
        assert_eq!(ResultKind::GeneratedArtifact.as_str(), "generated-artifact");
    }

    // ── normalize ────────────────────────────────────────────────────────────

    fn make_hit(intent: SearchIntent, result_kind: ResultKind, line: Option<u32>) -> RawSearchHit {
        RawSearchHit {
            file_path: "/repo/src/main.rs".into(),
            line_number: line,
            matched_text: "DATABASE_URL=postgres://localhost/app".into(),
            backend: "rg".into(),
            intent,
            result_kind,
            query: "DATABASE_URL".into(),
        }
    }

    #[test]
    fn normalize_sets_source_tool_to_searcher() {
        let hit = make_hit(SearchIntent::ConfigLookup, ResultKind::Config, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.source_tool, "searcher");
    }

    #[test]
    fn normalize_sets_probe_family_from_intent() {
        let hit = make_hit(SearchIntent::ErrorStringHunt, ResultKind::Log, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.probe_family, "error-string-hunt");
    }

    #[test]
    fn normalize_sets_target_to_file_path() {
        let hit = make_hit(SearchIntent::ConfigLookup, ResultKind::Config, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.target, "/repo/src/main.rs");
    }

    #[test]
    fn normalize_assigns_layer_7_for_config_lookup() {
        let hit = make_hit(SearchIntent::ConfigLookup, ResultKind::Config, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.layer, Some(7));
    }

    #[test]
    fn normalize_assigns_layer_6_for_schema_search() {
        let hit = make_hit(
            SearchIntent::SchemaOrPayloadSearch,
            ResultKind::StructuredText,
            None,
        );
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.layer, Some(6));
    }

    #[test]
    fn normalize_kind_is_static() {
        let hit = make_hit(SearchIntent::DependencyTracing, ResultKind::SourceCode, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.kind, EvidenceKind::Static);
    }

    #[test]
    fn normalize_status_is_propagated() {
        let hit = make_hit(
            SearchIntent::SecretOrConfigSurfaceDetection,
            ResultKind::Config,
            None,
        );
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Fail);
        assert_eq!(rec.status, DiagnosticStatus::Fail);
    }

    #[test]
    fn normalize_raw_refs_contains_matched_text() {
        let hit = make_hit(SearchIntent::ConfigLookup, ResultKind::Config, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert!(rec.raw_refs.contains(&"DATABASE_URL=postgres://localhost/app".to_string()));
    }

    #[test]
    fn normalize_metadata_contains_backend_and_result_kind() {
        let hit = make_hit(SearchIntent::ConfigLookup, ResultKind::Config, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.metadata.get("backend").map(String::as_str), Some("rg"));
        assert_eq!(
            rec.metadata.get("result_kind").map(String::as_str),
            Some("config")
        );
    }

    #[test]
    fn normalize_includes_line_number_in_metadata_when_present() {
        let hit = make_hit(SearchIntent::ErrorStringHunt, ResultKind::Log, Some(42));
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Fail);
        assert_eq!(
            rec.metadata.get("line_number").map(String::as_str),
            Some("42")
        );
    }

    #[test]
    fn normalize_summary_contains_query_and_intent() {
        let hit = make_hit(SearchIntent::EntryPointTracing, ResultKind::SourceCode, None);
        let rec = normalize(&hit, "2026-03-19T00:00:00Z", DiagnosticStatus::Pass);
        assert!(rec.summary.contains("entry-point-tracing"));
        assert!(rec.summary.contains("DATABASE_URL"));
    }

    // ── select_backend ───────────────────────────────────────────────────────

    #[test]
    fn select_backend_returns_rg_when_available() {
        let available = &["rg", "grep"];
        let backend = select_backend(BackendCapability::RecursiveSearch, available).unwrap();
        assert_eq!(backend.name, "rg");
    }

    #[test]
    fn select_backend_returns_preferred_first() {
        // rg and ag are both preferred for recursive search; rg comes first in catalog
        let available = &["ag", "rg", "grep"];
        let backend = select_backend(BackendCapability::RecursiveSearch, available).unwrap();
        assert_eq!(backend.name, "rg");
    }

    #[test]
    fn select_backend_falls_back_when_preferred_missing() {
        // rg and ag are missing; grep is the fallback
        let available = &["grep"];
        let backend = select_backend(BackendCapability::RecursiveSearch, available).unwrap();
        assert_eq!(backend.name, "grep");
    }

    #[test]
    fn select_backend_falls_back_to_peco_when_fzf_missing() {
        let available = &["peco"];
        let backend = select_backend(BackendCapability::InteractiveFilter, available).unwrap();
        assert_eq!(backend.name, "peco");
    }

    #[test]
    fn select_backend_returns_none_when_no_tool_available() {
        let available: &[&str] = &[];
        let backend = select_backend(BackendCapability::RecursiveSearch, available);
        assert!(backend.is_none());
    }

    #[test]
    fn select_backend_returns_none_when_no_capable_tool_available() {
        // grep has no interactive-filter capability
        let available = &["grep"];
        let backend = select_backend(BackendCapability::InteractiveFilter, available);
        assert!(backend.is_none());
    }

    #[test]
    fn select_backend_result_name_preserved_in_normalize() {
        // The backend name from select_backend should round-trip through normalize
        let available = &["grep"];
        let backend = select_backend(BackendCapability::RecursiveSearch, available).unwrap();
        let hit = RawSearchHit {
            file_path: "/repo/Cargo.toml".into(),
            line_number: None,
            matched_text: "tokio".into(),
            backend: backend.name.into(),
            intent: SearchIntent::DependencyTracing,
            result_kind: ResultKind::GeneratedArtifact,
            query: "tokio".into(),
        };
        let rec = normalize(&hit, "2026-03-20T00:00:00Z", DiagnosticStatus::Pass);
        assert_eq!(rec.metadata.get("backend").map(String::as_str), Some("grep"));
    }

    #[test]
    fn select_backend_preferred_false_when_only_fallback_available() {
        let available = &["grep"];
        let backend = select_backend(BackendCapability::RecursiveSearch, available).unwrap();
        assert!(!backend.preferred);
    }

    #[test]
    fn select_backend_structured_query_prefers_jq_over_ugrep() {
        let available = &["ugrep", "jq", "yq"];
        let backend = select_backend(BackendCapability::StructuredQuery, available).unwrap();
        // jq and yq are preferred; ugrep is not
        assert!(backend.preferred);
        assert!(backend.name == "jq" || backend.name == "yq");
    }
}
