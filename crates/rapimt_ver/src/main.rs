use std::{path::PathBuf, time::Instant};

use rapimt_core::r#match::engine::RuddyPredicateEngine;
use rapimt_ver::ib::snapshot::{SnapshotConfig, SnapshotQuery, SnapshotVerifier};

fn main() {
    let engine = RuddyPredicateEngine::init(10000, 5000);
    let config = SnapshotConfig {
        engine: &engine,
        topology_dir: PathBuf::from("examples/ibdiagnet2"),
        route_dir: PathBuf::from("examples/ibroute"),
    };
    let verifier = SnapshotVerifier::new(&config).unwrap();

    let before = Instant::now();
    println!(
        "actions for lid 0x0001: {:?}",
        verifier.query_lid(0x0001).unwrap().1
    );
    println!("query time: {:?}", before.elapsed());
    println!("#EC: {}", verifier.query_num_ec());
}
// Time of different parts:
// load topology files: 107.679375ms
// load route files: 2.861129246s
// merge local EC: 44.450319004s
// merge global EC: about 3 min
// single query time: 447.333µs
//
// actions for lid 0x0001: [8194, 8199, ..., 8224, 8224]
// #EC: 11797
