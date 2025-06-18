use std::{collections::HashMap, fs::read_to_string};

use rapimt_core::{action::seq_action::SeqAction, prelude::RuddyPredicateEngine};
use rapimt_im::{
    im::MapInverseModel,
    prelude::{FastRuleMonitor, InverseModel, RuleMonitorLike, TPTRuleStore},
};
use rapimt_io::{
    default::loader::PortInfoBase,
    prelude::{DefaultInstLoader, FibLoader, InstanceLoader},
};

/// Runs the Stanford dataset example, loading device specifications and FIBs, constructing per-device and network-wide inverse models, and validating the expected number of equivalence classes.
///
/// This function initializes the predicate engine and loaders, reads device topology and FIB files, builds rule monitors and device inverse models, merges them into a network-wide inverse model, and asserts that the resulting model contains exactly 155 equivalence classes for the Stanford dataset.
///
/// # Examples
///
/// ```
/// // To run the example, execute the binary:
/// // cargo run --example stanford
/// ```
fn main() {
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
}
