use std::{collections::HashMap, time::SystemTime};

use fxhash::FxHashMap;
use rapimt_core::prelude::RuddyPredicateEngine;
use rapimt_im::prelude::{FastRuleMonitor, InverseModel, RuleMonitor, TPTRuleStore};
use rapimt_io::prelude::{DefaultInstLoader, FibLoader, InstanceLoader, PortInfoBase, TypedAction};

fn main() {
    let engine = RuddyPredicateEngine::init(100, 10);
    let loader = DefaultInstLoader {};

    // get device names of dataset
    let mut devs = vec![];
    for entry in std::fs::read_dir("examples/stanford/fib").unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap();
        devs.push(name.to_string());
    }

    // load topology (port information)
    let mut codexs = FxHashMap::<String, PortInfoBase>::default();
    for dev in devs.iter() {
        let spec_cont =
            std::fs::read_to_string(format!("examples/stanford/spec/{}.spec", dev)).unwrap();
        let codex = InstanceLoader::load(&loader, &spec_cont).unwrap();
        codexs.insert(dev.clone(), codex);
    }

    // create monitors
    let mut monitors = FxHashMap::<String, FastRuleMonitor<_, _, TPTRuleStore<_, _>>>::default();
    for dev in codexs.keys() {
        monitors.insert(dev.clone(), FastRuleMonitor::new(&engine));
    }

    let mut mr1_timer = 0u128;
    let mut r2_timer = 0u128;

    // we choose FxHashMap to store the network-wide inverse model and Vec to store the actions.
    let mut im: InverseModel<_, _, _, FxHashMap<Vec<_>, _>> = InverseModel::default();
    let mut im_updates = HashMap::new();

    // load fibs and get inverse model of each device
    for d in codexs.keys() {
        let fib_cont = std::fs::read_to_string(format!("examples/stanford/fib/{}.fib", d)).unwrap();
        // load, parse and encode fib rules
        let fibs = codexs[d].load(&engine, &fib_cont).unwrap().1;
        let _timer = SystemTime::now();
        // feed fibs to the monitor and get the incremental update in the form of inverse model
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
        im_updates.insert(d.clone(), im_update);
    }

    // merge inverse models into one big network model
    for (d, im_update) in im_updates {
        let idx = devs.iter().position(|x| *x == d).unwrap();
        // expand usize to Vec<usize>
        let im_update = InverseModel::from(im_update);
        // resize local inverse model to network-wide inverse model
        let im_update = InverseModel::resize(im_update, devs.len(), idx);
        let _timer = SystemTime::now();
        im <<= im_update;
        r2_timer += _timer.elapsed().unwrap().as_nanos();
    }
    println!("Monitor refresh time: {} us", mr1_timer / 1000);
    println!("Inverse model << time: {} us", r2_timer / 1000);

    // the number of equivalent classes in this stanford dataset is 155
    assert_eq!(im.len(), 155)
}
