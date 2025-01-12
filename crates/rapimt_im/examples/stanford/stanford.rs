use std::time::SystemTime;

use fxhash::FxHashMap;
use rapimt_core::prelude::{RuddyPredicateEngine, OxiddPredicateEngine};
use rapimt_im::prelude::{FastRuleMonitor, InverseModel, RuleMonitor, TPTRuleStore};
use rapimt_io::prelude::{DefaultInstLoader, FibLoader, InstanceLoader, TypedAction};

fn main() {
    let engine = RuddyPredicateEngine::init(10_000, 1000);
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

    let mut mr1_timer = 0u128;
    let mut r2_timer = 0u128;

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
        let _timer = SystemTime::now();
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
        mr1_timer += _timer.elapsed().unwrap().as_nanos();
        im_updates.insert(d, im_update);
    }

    // 4. Merge incremental updates into one big network model
    for (d, im_update) in im_updates {
        let idx = devs.iter().position(|x| x == d).unwrap();
        // expand usize to Vec<usize>
        let im_update = InverseModel::from(im_update);
        // resize local inverse model to network-wide inverse model
        let im_update = InverseModel::resize(im_update, devs.len(), idx);
        let _timer = SystemTime::now();
        // merge the inverse model
        im <<= im_update;
        r2_timer += _timer.elapsed().unwrap().as_nanos();
    }
    println!("Monitor refresh time: {} us", mr1_timer / 1000);
    println!("Inverse model << time: {} us", r2_timer / 1000);

    // 5. Check the number of equivalent classes in the network-wide
    // The number of equivalent classes in this stanford dataset is 155
    assert_eq!(im.len(), 155)
}
