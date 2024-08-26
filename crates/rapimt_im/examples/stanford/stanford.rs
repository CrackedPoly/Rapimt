use std::{collections::HashMap, time::SystemTime};

use rapimt_core::{
    action::{seq_action::SeqActions, Multiple},
    r#match::{engine::RuddyPredicateEngine, family::MatchFamily},
};
use rapimt_im::{DefaultFibMonitor, FibMonitor, InverseModel};
use rapimt_io::{
    {DefaultInstLoader, PortInfoBase}, {FibLoader, InstanceLoader},
};

fn main() {
    let family = MatchFamily::Inet4Family;
    let engine = RuddyPredicateEngine::init(100, 10, family);
    let parser = DefaultInstLoader {};

    let devs = std::fs::read_dir("examples/stanford/fib")
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_str().unwrap();
            name.to_string()
        })
        .collect::<Vec<_>>();

    let codexs: HashMap<String, PortInfoBase> = devs
        .into_iter()
        .map(|dev| {
            let spec_cont =
                std::fs::read_to_string(format!("examples/stanford/spec/{}.spec", dev)).unwrap();
            let codex = InstanceLoader::load(&parser, &spec_cont).unwrap();
            (dev, codex)
        })
        .collect();

    let mut monitors: HashMap<String, DefaultFibMonitor<_, _>> = codexs
        .keys()
        .map(|k| (k.clone(), DefaultFibMonitor::new(&engine)))
        .collect();

    let mut monitor_timer = 0u128;
    let mut im_timer = 0u128;

    let mut im = InverseModel::default();
    let mut im_updates = HashMap::new();
    for d in codexs.keys() {
        let fib_cont = std::fs::read_to_string(format!("examples/stanford/fib/{}.fib", d)).unwrap();
        let fibs = FibLoader::load(&codexs[d], &engine, &fib_cont).unwrap().1;
        let _timer = SystemTime::now();
        let im_update = monitors
            .get_mut(d)
            .unwrap()
            .insert::<SeqActions<u32, 16>, Multiple>(fibs);
        monitor_timer += _timer.elapsed().unwrap().as_nanos();
        im_updates.insert(d.clone(), im_update);
    }

    let devs = codexs.keys().collect::<Vec<_>>();
    for (d, mut im_update) in im_updates {
        let idx = devs.iter().position(|&x| *x == d).unwrap();
        im_update.resize(devs.len(), idx);
        let _timer = SystemTime::now();
        im <<= im_update;
        im_timer += _timer.elapsed().unwrap().as_nanos();
    }
    println!("Monitor refresh time: {} us", monitor_timer / 1000);
    println!("Inverse model << time: {} us", im_timer / 1000);
    dbg!(im.len());
}
