# Rapimt Development Guide

This guide explains the pieces you will touch while building on top of Rapimt,
how the crates fit together, and the commands you can use to validate your
changes.  It complements the code-level docs in `src/lib.rs` and the Flash
paper reproduced in `docs/flash-sigcomm22.pdf`.

## Prerequisites
- **Rust nightly**: the repository pins a `rust-toolchain.toml` to the nightly
  channel.  Install it once with `rustup toolchain install nightly`.
- **Feature flags**: enable the header-space dimensions you need via Cargo
  features (`dip`, `sip`, `sport`, `dport`, `tag`, `lid`, `arc`).  The root
  crate documents all flags thanks to `document-features`.
- **Environment**: run commands from the workspace root; the repo is a Cargo
  workspace with several crates under `crates/`.

## Workspace Tour
- `rapimt` – facade crate that re-exports everything else, plus the top-level
  developer docs.
- `crates/rapimt_core` – match/action encoding, predicate engines (Ruddy/OxiDD),
  helper macros such as `fm_ipv4_from!`.
- `crates/rapimt_im` – inverse model algebra (see `im.rs`) and rule monitors
  (`FastRuleMonitor`, `IbRuleMonitor`) that generate device IM updates.
- `crates/rapimt_io` – parsers and loaders for router configs (`default`) and
  InfiniBand snapshots (`ib`).
- `crates/rapimt_tpt` – ternary Patricia tree implementation used by the
  default rule store.
- `crates/rapimt_ver` – graph-based verification engine, plugins, and the
  `SnapshotVerifier`.
- `crates/rapimt_cli` – CLI and HTTP server for InfiniBand use cases.
- `docs/` – design notes and this guide; `docs/flash-sigcomm22.pdf` captures the
  theory behind inverse model transformation.

## Build & Test Commands
- `cargo fmt --all` – format the workspace (see `CONTRIBUTING.md`).
- `cargo test` or `cargo test -p rapimt_core` – run tests for the full workspace
  or a specific crate.
- `cargo run -p rapimt_io --example stanford` – run the Stanford topology demo.
- `cargo run -p rapimt_cli --bin ib_oneshot_check -- --help` – inspect the IB
  verification CLI flags.
- `cargo run -p rapimt_cli --bin ib_server -- --topology-dir ...` – launch the
  HTTP API documented in `docs/ib_server.md`.

## Development Workflow

### 1. Choose a predicate engine and header set
Select a predicate engine (see `crates/rapimt_core/src/match/engine`) and
enable the features that describe your header fields.  `RuddyPredicateEngine`
uses the RuDDy BDD implementation and works well for quick experiments.  The
`OxiddPredicateEngine` is multi-thread friendly and is what the InfiniBand
snapshot tooling uses.  Each engine exposes `one`, `zero`, serialization helpers,
and field-rewrite helpers (e.g. `rewrite_dip`).

### 2. Encode topology and actions
An action encoder (`crates/rapimt_core/src/action`) converts rich
uncoded actions into opaque,
hashable values that an inverse model can store.  The default router loader
(`rapimt_io::default::loader::DefaultInstLoader`) parses `.spec` files into
`PortInfoBase` encoders; for other devices implement your own encoder that
knows how to look up ports and neighbors.  Turn on the `arc` feature if the
topology data needs to be shared across threads (`Arc` instead of `Rc`).

### 3. Parse forwarding rules
Use a FibLoader (trait defined in `crates/rapimt_io/src/default/mod.rs`) to parse forwarding entries
into `Rule<Predicate, Action>` pairs.  The default loader supports textual
`fw` lines with prefixes and port names.  For custom formats, follow the pattern
in `crates/rapimt_io/src/default/loader.rs`: parse into `RawRule`, reuse
`FieldMatch` helpers (e.g. `fm_ipv4_from!`), then encode with your action
encoder.  The loader lifetime ties the action encoder and predicate engine
lifetimes together (`'a == 'p`), so keep the encoder alive while the rules are
in use.

### 4. Generate per-device inverse models
Create a `FastRuleMonitor` per device (see `crates/rapimt_im/src/default/monitor.rs`).
Pick a `RuleStore`
implementation that works for your match patterns:

| Store            | When to use it                                      |
| ---------------- | --------------------------------------------------- |
| `TPTRuleStore`   | Prefix-dominant tables; backed by
                    `TernaryPatriciaTree`.                               |
| `SimpleRuleStore`| Small device tables; stores a sorted `BTreeSet`.    |

Feed insert/delete iterators into `monitor.update(...)` (or `insert` /
`delete` helpers).  The first call returns the current device state; later calls
return incremental updates.  Each update is an inverse model that maps
actions to predicates.  Call `property_check()` during development to ensure
updates remain mutually exclusive and complete.

### 5. Compose the network model
For network-wide reasoning, express each per-device inverse model as a
`SeqAction` via `InverseModel::resize` and left-shift them into an aggregate
`MapInverseModel`.  The Stanford sample
(`crates/rapimt_io/examples/stanford/stanford.rs`) shows the exact loop.  The
pattern is always:

```rust
let update = monitor.insert(device_rules);
let idx = device_index_in_network;
let sized = InverseModel::resize(update, num_devices, idx);
global_im <<= sized;
```

Once the model is merged you can inspect the number of equivalent classes with
`map.len()` or enumerate the `(action, predicate)` pairs via `.iter()`.

### 6. Dispatch verification logic
`rapimt_ver` takes the inverse model output and turns it into forwarding DAGs.
`SnapshotVerifier` (used for InfiniBand) consumes a data plane that implements
the `DataPlane` trait (`crates/rapimt_io/src/ib/mod.rs`): it knows how to load topology,
transform `RawRuleLike` items into encoded rules, and generate IM deltas.
Register `GraphPluginLike` implementations
implementations to run invariants on every simple path.  The existing
`SimplePathExactRegexSetPlugin` counts regex-matched path shapes, and the
`plugin::rsl` module parses a requirement DSL into predicates and regexes.

## Working with InfiniBand Snapshots
- `IbDataPlane` (in `crates/rapimt_io/src/ib/loader.rs`) loads topology (`nodes`,
  `group`, and `lft` directories) exported by `ibdiagnet2`.
- `SnapshotVerifier` wraps the data plane, maintains IM updates, builds forward
  graphs per action pattern, and exposes a `SnapshotQuery` API (see
  `crates/rapimt_ver/src/lib.rs`).
- `crates/rapimt_cli/src/bin/ib_oneshot_check.rs` builds a verifier once, runs
  regex-based plugins, and exits.  Use it to sanity-check an IB dataset:
  ```
  cargo run -p rapimt_cli --bin ib_oneshot_check -- \
      -t ibdiagnet2.db_csv -r ibdiagnet2.far \
      -p LH:1,LSLH:896
  ```
- `crates/rapimt_cli/src/bin/ib_server.rs` starts an Axum HTTP server (see
  `docs/ib_server.md`) that exposes `/api/v1/num_ec`, `/api/v1/alert`, and
  `/api/v1/dag/{lid}` endpoints backed by `SnapshotQuery`.

## Extending Rapimt
1. **Model the header space** – add new match fields to
   `crates/rapimt_core/build.rs` or reuse the existing field declarations.
2. **Implement an action encoder** – model your device’s forwarding primitives
   by implementing `ActionEncoder` + `UncodedAction`.
3. **Parse the control-plane data** – write an `InstanceLoader` and `FibLoader`
   or adapt the InfiniBand `DataPlane` trait for snapshot ingestion.
4. **Choose a rule store** – either reuse `FastRuleMonitor`/`TPTRuleStore` or
   implement `RuleMonitorLike`/`RuleStore` tailored to your hardware.
5. **Integrate with verification** – convert the new inverse model output into
   the data structures expected by your plugins (`SeqAction`, graph nodes,
   etc.) and register them with `SnapshotVerifier` (or your own verifier).

See also `docs/device_compatibility.md` for device-porting checklists.

## Verification Plugins & RSL
- Implement `GraphPluginLike` for graph-only invariants or
  `VerifierPluginLike` if the plugin has to filter by header space via a
  predicate (`header_space` method).
- `plugin::regexset` contains a ready-to-use regex matcher that tracks whether
  each expected pattern was seen.  It serializes reports via `serde` and
  `typetag`.
- `plugin::rsl` parses the Requirement Specification Language (see
  `crates/rapimt_ver/src/plugin/rsl.pest`) into predicates and node/path
  constraints.  Use it to feed plugins from a text file instead of Rust code.

## Debugging Tips
- Call `Predicate::is_empty()` and `InverseModel::property_check()` liberally
  while developing new rules or monitors.
- Monitor BDD usage with `engine.gc()` (returns reclaimed node count).
- Enable logging (`RUST_LOG=info cargo run ...`) to trace snapshot refreshes,
  plugin registrations, and HTTP handlers.
- `SnapshotVerifier::verify()` is idempotent; call it after injecting new
  updates when running in long-lived processes (e.g. the server).

## References & Examples
- Stanford equivalent-class example:
  `crates/rapimt_io/examples/stanford/stanford.rs`.
- InfiniBand end-to-end flow: `crates/rapimt_cli/src/ib`.
- Theory background: `docs/flash-sigcomm22.pdf`.
- Device compatibility notes: `docs/device_compatibility.md`.
- API description for the HTTP server: `docs/ib_server.md`.

Use this guide as a map when navigating the code; the inline Rustdocs and source
comments mentioned above explain the remaining implementation details.
