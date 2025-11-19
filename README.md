# Rapimt

Rapimt implements the Flash inverse model transformation pipeline
(see [`docs/flash-sigcomm22.pdf`]) entirely in Rust. The crate that you
depend on (`rapimt`) is a lightweight facade over a set of internal
crates that cover predicate engines, inverse model arithmetic, device
IO, and pluggable verification logic.

## Workspace layout

- `rapimt::core` &mdash; header-space encoders, predicate engines (Ruddy
  and Oxidd), match macros, and forwarding action traits.
- `rapimt::im` &mdash; inverse model data structures plus rule monitors
  such as [`FastRuleMonitor`].
- `rapimt::io` &mdash; parsers and loaders (default router format and
  InfiniBand snapshots).
- `rapimt::ver` &mdash; graph-based verification drivers and plugins.
- `rapimt::prelude` &mdash; re-exports of the symbols most developers
  reach for (`use rapimt::prelude::*;`).

## Typical workflow

1. Pick a [`PredicateEngine`]
   (Ruddy for fast single-threaded prototyping, Oxidd for multi-threaded
   production runs) and enable the feature flags for the header fields you
   care about (`dip`, `sip`, `sport`, ...).
2. Load topology information with an [`InstanceLoader`]
   or your own device specific loader and obtain an
   [`ActionEncoder`].
3. Parse the device FIB into [`Rule`] objects via [`FibLoader`].
4. Feed incremental changes into a [`RuleMonitor`] (e.g. [`FastRuleMonitor`])
   to generate per-device inverse models.
5. Resize and merge device models into a network-wide [`InverseModel`],
   then dispatch verification plugins.

```rust,no_run
use rapimt::core::prelude::{SeqAction, RuddyPredicateEngine};
use rapimt::io::prelude::{InstanceLoader, DefaultInstLoader, FibLoader, PortInfoBase};
use rapimt::im::prelude::{RuleMonitorLike, FastRuleMonitor, InverseModel, MapInverseModel, TPTRuleStore};

fn demo() -> Result<(), Box<dyn std::error::Error>> {
  let engine = RuddyPredicateEngine::init(10_000, 1_000);
  let loader = DefaultInstLoader::default();

  // Load the action encoder for a device.
  let spec = std::fs::read_to_string("specs/dev0.spec")?;
  let codex: PortInfoBase = loader.load(&spec).unwrap();

  // Parse the FIB and insert rules into a monitor.
  let fib = std::fs::read_to_string("fibs/dev0.fib")?;
  let (_, rules) = codex.load(&engine, &fib).unwrap();
  let mut monitor: FastRuleMonitor<_, _, TPTRuleStore<_, _>> =
      FastRuleMonitor::new(&engine);
  let update: MapInverseModel<SeqAction<usize>, _, _> = monitor.insert(rules);
  assert!(update.property_check());

  // Resize/merge updates for a multi-device network.
  let mut net: MapInverseModel<SeqAction<usize>, _, _> = InverseModel::default();
  net <<= InverseModel::resize(update, /*num_devices*/ 1, /*offset*/ 0);
  Ok(())
}
```

For a longer, end-to-end walkthrough read `docs/development.md`.

## Feature flags

The crate documentation includes an auto-generated table of all feature
flags via `document_features::document_features!()`.

[`docs/flash-sigcomm22.pdf`]: https://raw.githubusercontent.com/CrackedPoly/Rapimt/refs/heads/main/docs/flash-sigcomm22.pdf
[`FastRuleMonitor`]: https://crackedpoly.github.io/Rapimt/rapimt/im/default/monitor/struct.FastRuleMonitor.html
[`PredicateEngine`]: https://crackedpoly.github.io/Rapimt/rapimt/core/match/engine/trait.PredicateEngine.html
[`InstanceLoader`]: https://crackedpoly.github.io/Rapimt/rapimt/io/default/trait.InstanceLoader.html
[`ActionEncoder`]: https://crackedpoly.github.io/Rapimt/rapimt/core/action/trait.ActionEncoder.html
[`Rule`]: https://crackedpoly.github.io/Rapimt/rapimt/im/default/rule/struct.Rule.html
[`FibLoader`]: https://crackedpoly.github.io/Rapimt/rapimt/io/default/trait.FibLoader.html
[`RuleMonitor`]: https://crackedpoly.github.io/Rapimt/rapimt/im/trait.RuleMonitorLike.html
[`InverseModel`]: https://crackedpoly.github.io/Rapimt/rapimt/im/struct.InverseModel.html
