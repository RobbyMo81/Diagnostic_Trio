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

- **Discover** — classifies repository and host evidence into OSI layer-tagged findings using probe families (filesystem, process, network, config, dependency, log, certificate)
- **Searcher** — searches across 13 configurable backends (ripgrep, fd, grep, find, etc.), normalizes results by intent (config lookup, error-string hunt, entry-point tracing, dependency tracing, schema/payload search, secret surface detection), and degrades gracefully when preferred tools are unavailable
- **Trace** — collects live runtime evidence across 8 target types (processes, listeners/ports, routes/interfaces, sessions, logs, payload/protocol, runtime dependencies, bind/transport anomalies)

## Architecture

Evidence flows through a shared `EvidenceRecord` schema understood by all three capabilities. Findings are classified by OSI layer (L1–L7) and tagged with a diagnostic status (`blocked`, `pass`, `fail`, `partial`, `not-tested`). A lower-layer blocking rule prevents upper layers from being treated as healthy when a lower layer is failed or untested.

Significant work is appended to a shared JSONL journal for audit continuity. Journal entries link back to originating evidence records via `evidence_ref`.

### Safety model

Runtime inspection is **read-only by default**. Sensitive inspection paths (e.g., session capture, payload/protocol inspection, host-scope discovery) require explicit `Authorized` safety level. All other targets operate at `ReadOnly`.

### Language boundary

| Responsibility | Component |
|----------------|-----------|
| CLI, host execution, orchestration, normalization, MCP exposure | `trio-host` (Rust) |
| Reasoning, interpretation, synthesis, narrative generation | `trio-reason` (Python) |

### Workspace layout

```
<workspace>/
  artifacts/   # durable finding artifacts
  cache/       # transient tool caches
  journal/     # append-only JSONL audit log
  state/       # shared run state
```

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
python -m venv /tmp/trio-venv && source /tmp/trio-venv/bin/activate
pip install -e ".[dev]"
mypy trio_reason tests
pytest
```

> **Note:** Use a virtual environment — the system Python is externally managed (PEP 668).

## Implementation status

| Story | Title | Status |
|-------|-------|--------|
| US-001 | Project scaffold | complete |
| US-002 | Shared evidence schema | complete |
| US-003 | Shared workspace and state contract | complete |
| US-004 | Layer and status model | complete |
| US-005 | Discover evidence classification | complete |
| US-006 | Searcher backend catalog | complete |
| US-007 | Searcher result normalization | complete |
| US-008 | Trace runtime evidence capture | complete |
| US-009 | Runtime safety gating | complete |
| US-010 | Shared journal | complete |
| US-011 | Artifact write-back behavior | pending |
| US-012 | Rust/Python boundary documentation | pending |
| US-013 | Search backend fallback behavior | pending |
| US-014 | Family architecture documentation | pending |

## Automation

`ralph.sh` is an agent loop that drives autonomous implementation of user stories from `prd.json`. It supports both `amp` and `claude` as backing tools and archives progress between runs.

```sh
./ralph.sh --tool claude 5   # run up to 5 iterations with Claude
./ralph.sh --tool amp        # run with Amp (default, 10 iterations)
```

See `prd.json` for the full specification and story breakdown.
