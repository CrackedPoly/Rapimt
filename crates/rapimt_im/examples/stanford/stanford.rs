use std::{collections::HashMap, time::SystemTime};

use fxhash::FxHashMap;
use rapimt_core::{
    action::{seq_action::SeqActions, Multiple},
    r#match::{engine::RuddyPredicateEngine, family::MatchFamily},
};
use rapimt_im::{DefaultFibMonitor, FibMonitor, InverseModel};
use rapimt_io::{DefaultInstLoader, FibLoader, InstanceLoader, PortInfoBase};

fn main() {
    let family = MatchFamily::Inet4Family;
    let engine = RuddyPredicateEngine::init(100, 10, family);
    let parser = DefaultInstLoader {};

    // get device names of dataset
    let mut devs = vec![];
    for entry in std::fs::read_dir("examples/stanford/fib").unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap();
        devs.push(name.to_string());
    }

    // load port information
    let mut codexs = FxHashMap::<String, PortInfoBase>::default();
    for dev in devs.iter() {
        let spec_cont =
            std::fs::read_to_string(format!("examples/stanford/spec/{}.spec", dev)).unwrap();
        let codex = InstanceLoader::load(&parser, &spec_cont).unwrap();
        codexs.insert(dev.clone(), codex);
    }

    // create monitors
    let mut monitors = FxHashMap::<String, DefaultFibMonitor<_, _>>::default();
    for dev in codexs.keys() {
        monitors.insert(dev.clone(), DefaultFibMonitor::new(&engine));
    }

    let mut monitor_timer = 0u128;
    let mut im_timer = 0u128;

    let mut im = InverseModel::default();
    let mut im_updates = HashMap::new();

    // load fibs and get inverse model of each device
    for d in codexs.keys() {
        let fib_cont = std::fs::read_to_string(format!("examples/stanford/fib/{}.fib", d)).unwrap();
        let fibs = FibLoader::load(&codexs[d], &engine, &fib_cont).unwrap().1;
        let _timer = SystemTime::now();
        let im_update = monitors
            .get_mut(d)
            .unwrap()
            .insert::<SeqActions<usize, 16>, Multiple>(fibs);
        monitor_timer += _timer.elapsed().unwrap().as_nanos();
        im_updates.insert(d.clone(), im_update);
    }

    // merge inverse models into one big network model
    for (d, mut im_update) in im_updates {
        let idx = devs.iter().position(|x| *x == d).unwrap();
        im_update.resize(devs.len(), idx);
        let _timer = SystemTime::now();
        im <<= im_update;
        im_timer += _timer.elapsed().unwrap().as_nanos();
    }
    println!("Monitor refresh time: {} us", monitor_timer / 1000);
    println!("Inverse model << time: {} us", im_timer / 1000);

    // the number of equivalent classes in this stanford dataset is 155 (through a ton of tests)
    assert_eq!(im.len(), 155)
}
