# Diagnostic Trio — Family Architecture

Diagnostic Trio is a modular diagnostic tool family. Three companion capabilities —
**Discover**, **Searcher**, and **Trace** — share a common evidence contract,
workspace, and journal. Each capability is independently useful; together they
provide layered, reproducible diagnostics without depending on Diagnostic Quartet
internals.

---

## Companion Capabilities

| Capability | Source domain | Evidence kind | Role |
|------------|---------------|---------------|------|
| **Discover** | Repository and host filesystem | Static | Classifies configuration, process, network, dependency, log, and certificate evidence into OSI-layer-tagged findings |
| **Searcher** | File trees, source code, structured text, logs | Static | Searches across 13 configurable backends by intent; normalizes results into the shared evidence schema |
| **Trace** | Live host runtime | Runtime | Interrogates running processes, listeners, routes, sessions, logs, payload behavior, runtime dependencies, and transport anomalies |

The three capabilities are **companions**, not a pipeline. Any combination can be
invoked without the others being present. When combined, evidence from all three
feeds into a single shared workspace, making cross-capability correlation
possible through the shared `EvidenceRecord` schema and journal.

---

## Operating Flows

### 1. Initial Setup

Purpose: establish workspace and baseline evidence for a new target.

Steps:
1. Initialise a fresh workspace (`WorkspaceLayout.from_root`).
2. Populate `SharedState` with target, search roots, and any tool-specific
   scopes (`discover_scope`, `search_query`, `trace_scope`).
3. Run **Discover** across repository and host to collect static baseline.
4. Run **Searcher** for known entry-point and configuration patterns.
5. Append significant findings to the shared journal.
6. Write durable artifacts (`discover-findings.jsonl`, `searcher-findings.jsonl`).

### 2. Layered Diagnosis

Purpose: systematically isolate failure surfaces using the OSI layer model.

Steps:
1. Load existing artifacts and journal from the workspace (if present).
2. Run **Trace** to collect live runtime evidence.
3. Apply the lower-layer blocking rule: findings at layer N are suppressed
   as healthy if any layer below N has status `fail`, `blocked`, or
   `not-tested`.
4. Group evidence by `layer` and `status` to identify the lowest failing
   surface.
5. Correlate static (Discover/Searcher) and runtime (Trace) findings at the
   same layer for cross-capability confirmation.
6. Append the diagnosis session to the journal with `evidence_ref` links.

### 3. Maintenance / Drift Detection

Purpose: detect configuration drift or regressions against a known-good baseline.

Steps:
1. Load a previous run's artifacts as the baseline.
2. Run **Discover** and **Searcher** against the current state.
3. Compare current findings against baseline by target, probe family, and layer.
4. Flag any finding whose `status` regressed (e.g., `pass` → `fail`) or
   whose `summary` changed for the same target.
5. Emit a `MaintenanceDrift` journal entry for each detected regression.
6. Write updated artifacts to preserve the new state for future comparisons.

---

## Relationship Between Capabilities

```
SharedState
    │
    ├─► Discover ──────────────────────────────────────► EvidenceRecord (Static)
    │       └── probe families: filesystem, process,              │
    │           network, config, dependency, log, cert            │
    │                                                             ▼
    ├─► Searcher ──────────────────────────────────────► EvidenceRecord (Static)
    │       └── intents: config-lookup, error-hunt,               │
    │           entry-point, dependency, schema, secret           ▼
    │                                                    Shared Workspace
    └─► Trace ────────────────────────────────────────► EvidenceRecord (Runtime)
            └── targets: processes, listeners, routes,            │
                sessions, logs, payload, runtime-deps,            │
                transport-anomalies                               ▼
                                                        Journal (JSONL)
                                                                  │
                                                                  ▼
                                                        Artifacts (JSONL)
```

Evidence flows from each capability into the shared workspace as immutable
`EvidenceRecord` values. The journal provides the append-only audit trail; the
artifact files provide the durable, queryable finding store.

---

## Extension Points

### Adding a New Probe Family (Discover)

1. Add a variant to `DiscoverProbeFamily` in `trio-host/src/discover.rs` and
   `trio-reason/trio_reason/discover.py`.
2. Implement `default_layer()` / `as_str()` for the new family.
3. Extend `classify()` to accept the new family — it already produces a generic
   `EvidenceRecord`, so no schema change is needed.
4. Add tests for the new family's layer assignment and output shape.

The core evidence model (`EvidenceRecord`) is **not changed**. The new family
emits the same schema with `probe_family` set to its own identifier.

### Adding a New Search Backend (Searcher)

1. Add a `SearchBackend` entry to `CATALOG` in `searcher.rs` / `searcher.py`
   with the appropriate `BackendCategory`, `preferred` flag, and
   `BackendCapability` set.
2. `backends_with_capability` and `select_backend` will automatically include
   the new entry. No other code changes are required.
3. Add catalog tests to verify the new backend's category, preferred status, and
   capabilities.

### Adding a New Trace Target

1. Add a variant to `TraceTarget` in `trio-host/src/trace.rs` and
   `trio-reason/trio_reason/trace.py`.
2. Implement `default_layer()` / `as_str()` and add the target's
   `required_safety_level()` to `safety.py` / `safety.rs`.
3. `capture()` already produces a generic `EvidenceRecord` tagged with
   `EvidenceKind::Runtime`, so no schema change is needed.

### Exposing Capabilities via MCP

MCP exposure is a Rust-side responsibility (`trio-host`). To expose a new
operation:

1. Add a handler in `main.rs` (or a dedicated `mcp.rs` module) that invokes the
   appropriate Rust function (`classify`, `normalize`, `capture`, etc.).
2. Serialise the resulting `EvidenceRecord` using `format_record` from
   `artifact.rs` and return it to the MCP caller.
3. The Python reasoning layer (`trio-reason`) is **not involved** in MCP
   serialisation; it remains responsible only for reasoning, interpretation,
   synthesis, and narrative generation.

---

## Design Principles

- **Schema stability first** — `EvidenceRecord` is the stable contract. All
  extension happens by adding variants to enums, not by changing the record
  itself.
- **Read-only by default** — runtime inspection requires explicit `Authorized`
  safety level; all static inspection is `ReadOnly`.
- **Append-only audit** — the journal is never rewritten; artifacts accumulate
  evidence across runs.
- **Language boundary is firm** — Rust handles execution, I/O, and MCP;
  Python handles reasoning and narrative. The boundary is the JSONL bridge
  message stream.
- **No Quartet dependency** — Trio reads from and writes to its own workspace
  layout without importing or calling any Quartet component.
