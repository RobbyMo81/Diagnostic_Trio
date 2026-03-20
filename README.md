# Diagnostic Trio

Diagnostic Trio is a modular diagnostic tool family integrating three companion
capabilities — **Discover**, **Searcher**, and **Trace** — around a shared
workspace, evidence contract, and journal flow.

It is designed to operate as a standalone toolset without depending on
Diagnostic Quartet internals.

## Components

| Component | Language | Role |
|-----------|----------|------|
| `trio-host` | Rust | CLI, host interaction, orchestration, normalization, MCP exposure |
| `trio-reason` | Python | Reasoning, interpretation, synthesis, narrative generation |

## Capabilities

- **Discover** — classifies repository and host evidence into layer-tagged findings
- **Searcher** — searches across configurable backends and normalizes results by intent
- **Trace** — collects live runtime evidence for behavior unavailable from static inspection

## Development

### Rust (trio-host)

```sh
cargo build
cargo test
cargo clippy
```

### Python (trio-reason)

```sh
cd trio-reason
pip install -e ".[dev]"
mypy .
pytest
```

## Architecture

Evidence flows through a shared schema understood by all three capabilities.
Findings are classified by OSI layer and tagged with a diagnostic status
(`blocked`, `pass`, `fail`, `partial`, `not-tested`). Significant work is
appended to a shared journal for audit continuity.

See `prd.json` for the full specification and story breakdown.
