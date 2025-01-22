use std::path::PathBuf;

use rapimt_core::r#match::engine::RuddyPredicateEngine;
use rapimt_ver::ib::{
    requirement::{label_node_topo_type, SimplePathExactRegexSetPlugin},
    snapshot::{IbDataPlaneConfig, SnapshotVerifier},
    SnapshotQuery,
};

fn main() {
    let engine = RuddyPredicateEngine::init(10000, 5000);
    let config = IbDataPlaneConfig {
        engine: &engine,
        topology_dir: PathBuf::from("examples/ibdiagnet2"),
        far_dir: PathBuf::from("examples/ibdiagnet2/far"),
        label_fn: label_node_topo_type,
    };
    let mut verifier = SnapshotVerifier::new(&config).unwrap();
    // INFO: L: Leaf switch, S: Spine switch, C: Core switch, H: Host
    let plugin = Box::new(SimplePathExactRegexSetPlugin::new(
        "Simple path Regex set count",
        [("LH", 0), ("LSLH", 0), ("LSCSLH", 0)],
    ));
    verifier.register_plugin(plugin);
    verifier.refresh().unwrap();

    println!("#EC: {}", verifier.query_num_ec());
}
