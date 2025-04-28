# [Rap]()id [I]()nverse [M]()odel [T]()ransformation

[![Test](https://github.com/CrackedPoly/Rapimt/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/CrackedPoly/Rapimt/actions/workflows/tests.yml)
[![Docs](https://github.com/CrackedPoly/Rapimt/actions/workflows/docs.yml/badge.svg)](https://github.com/CrackedPoly/Rapimt/actions/workflows/docs.yml)

Inverse Model Transformation in Rust

## Introduction

Rapimt is a data plane verification framework written in Rust.

## Features

- currently supported match fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `vlan`
- predicate engines: `Ruddy`, `OxiDD`
- verification functions: TODO

## Example

How many equivalent classes are there in a network? Compute it by Inverse
Model! (see the full example in `crates/rapimt_io/examples/stanford`)

```rust
let engine = RuddyPredicateEngine::init(10_000, 1000);
let loader = DefaultInstLoader {};
let devs = vec![
    "bbra_rtr", "bbrb_rtr", "boza_rtr", "bozb_rtr", "coza_rtr", "cozb_rtr", "goza_rtr",
    "gozb_rtr", "poza_rtr", "pozb_rtr", "roza_rtr", "rozb_rtr", "soza_rtr", "sozb_rtr",
    "yoza_rtr", "yozb_rtr",
];

// 1. Load topology (port information)
let codexes: HashMap<&str, PortInfoBase> = devs
    .iter()
    .map(|&d| {
        let spec_cont = read_to_string(format!("examples/stanford/spec/{}.spec", d)).unwrap();
        let codex = loader.load(&spec_cont).unwrap();
        (d, codex)
    })
    .collect();

// 2. Create rule monitors
let mut monitors: HashMap<&str, FastRuleMonitor<_, _, TPTRuleStore<_, _>>> = devs
    .iter()
    .map(|&d| (d, FastRuleMonitor::<_, _, _>::new(&engine)))
    .collect();

// 3. Load fibs and convert them into incremental updates (or we call it Device Inverse Model)
let im_updates = devs.iter().map(|&d| {
    let fib_cont = read_to_string(format!("examples/stanford/fib/{}.fib", d)).unwrap();
    let fibs = codexes[d].load(&engine, &fib_cont).unwrap().1;
    let im_update: MapInverseModel<SeqAction<usize>, _, _> =
        monitors.get_mut(d).unwrap().insert(fibs);
    (d, im_update)
});

// 4. Merge incremental updates into one big network model (or we call it Network Inverse Model)
let im: MapInverseModel<SeqAction<usize>, _, _> = im_updates
    .map(|(d, im_update)| {
        let idx = devs.iter().position(|&x| x == d).unwrap();
        // resize device inverse model to the right network index
        InverseModel::resize(im_update, devs.len(), idx)
    })
    .reduce(|mut x, y| {
        x <<= y;
        x
    })
    .unwrap();

// 5. Check the number of equivalent classes in the network-wide
// The number of equivalent classes in this stanford dataset is 155
assert_eq!(im.len(), 155)
```

## TODO List

- [x] Use patricia tree to store rules in a device
- [x] Optimize the inverse model resizing
- [ ] Port [TOBDD][2] predicate engine to Rust
- [ ] Benchmark the performance in larger datasets
- [ ] Implement more verification modules, such as the paper ["Modular DPV for
  Compositional Networks"][3]

## Reference

[1] S. Chen, J. Luo, D. Guo, K. Gao and Y. R. Yang, "Fast Inverse Model Transformation: Algebraic Framework for Fast Data Plane Verification", in IEEE Transactions on Dependable and Secure Computing.

[2] Dong Guo, Jian Luo, Kai Gao, and Y. Richard Yang, "Poster: Scaling Data Plane Verification with Throughput-Optimized Atomic Predicates", (ACM SIGCOMM '23).

[3] Xu Liu, Peng Zhang, Hao Li, and Wenbing Sun, "Modular Data Plane Verification for Compositional Networks", (ACM CoNEXT '23).

## License
