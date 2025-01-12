# [Rap]()id [I]()nverse [M]()odel [T]()ransformation

[![Test](https://github.com/CrackedPoly/Rapimt/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/CrackedPoly/Rapimt/actions/workflows/tests.yml)
[![Docs](https://github.com/CrackedPoly/Rapimt/actions/workflows/docs.yml/badge.svg)](https://github.com/CrackedPoly/Rapimt/actions/workflows/docs.yml)

Inverse Model Transformation in Rust

## Introduction

Rapimt is a data plane verification framework written in Rust.

## Features

- currently supported match fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `vlan`
- predicate engines: `Ruddy`, 'OxiDD'
- verification functions: TODO

## Example

How many equivalent classes are there in a network? Compute it by Inverse
Models!

```rust
let engine = RuddyPredicateEngine::init(100, 10);
let loader = DefaultInstLoader {};
let devs = vec![
    "bbra_rtr", "bbrb_rtr", "boza_rtr", "bozb_rtr", "coza_rtr", "cozb_rtr", "goza_rtr",
    "gozb_rtr", "poza_rtr", "pozb_rtr", "roza_rtr", "rozb_rtr", "soza_rtr", "sozb_rtr",
    "yoza_rtr", "yozb_rtr",
];

// 1. Load topology (port information)
let mut codexs = FxHashMap::default();
for dev in devs.iter() {
    let spec_cont =
        std::fs::read_to_string(format!("examples/stanford/spec/{}.spec", dev)).unwrap();
    let codex = InstanceLoader::load(&loader, &spec_cont).unwrap();
    codexs.insert(dev, codex);
}

// 2. Create rule monitors
let mut monitors = FxHashMap::default();
for dev in devs.iter() {
    monitors.insert(dev, FastRuleMonitor::<_, _, TPTRuleStore<_, _>>::new(&engine));
}

// Global inverse model
// We choose FxHashMap to store the network-wide inverse model and Vec to store the actions.
let mut im: InverseModel<_, _, _, FxHashMap<Vec<_>, _>> = InverseModel::default();
// Incremental updates
let mut im_updates = FxHashMap::default();

// 3. Load fibs and get incremental updatek of each device
for d in devs.iter() {
    let fib_cont = std::fs::read_to_string(format!("examples/stanford/fib/{}.fib", d)).unwrap();
    // Load, parse and encode fib rules
    let fibs = codexs[d].load(&engine, &fib_cont).unwrap().1;
    // Feed fibs to the monitor and get the incremental update in the form of inverse model
    // NOTICE:
    //   1. we use FxHashMap to store the inverse model entries.
    //   2. we use usize to represent an action in the device, alternatively, we can use
    //      TypedAction here.
    let im_update = monitors
        .get_mut(d)
        .unwrap()
        .insert::<_, _, FxHashMap<usize, _>>(fibs);
    // .insert::<_, _, FxHashMap<TypedAction, _>>(fibs);
    im_updates.insert(d, im_update);
}

// 4. Merge incremental updates into one big network model
for (d, im_update) in im_updates {
    let idx = devs.iter().position(|x| x == d).unwrap();
    // expand usize to Vec<usize>
    let im_update = InverseModel::from(im_update);
    // resize local inverse model to network-wide inverse model
    let im_update = InverseModel::resize(im_update, devs.len(), idx);
    // merge the inverse model
    im <<= im_update;
}

// 5. Check the number of equivalent classes in the network-wide
// The number of equivalent classes in this stanford dataset is 155
assert_eq!(im.len(), 155)
```

## Installation

## TODO List

- [x] Use patricia tree to store rules in a device
- [x] Optimize the inverse model resizing
- [ ] Benchmark the performance in larger datasets
- [ ] Implement more verification modules, such as the paper "Modular DPV for
  Compositional Networks"

## Reference

## License
