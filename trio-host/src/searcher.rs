//! Searcher backend catalog for Diagnostic Trio.
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
//! backend runs (see US-007 for result normalisation).

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
}
