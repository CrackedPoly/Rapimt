pub mod server;

use clap::Parser;
use rapimt_io::ib::IbDataPlaneConfig;
use std::{path::PathBuf, sync::Arc};

use rapimt_core::r#match::engine::MatchEncoder;
use rapimt_ver::{
    plugin::{GraphPluginLike, regexset::{label_node_topo_type, SimplePathExactRegexSetPlugin}},
    ib::snapshot::SnapshotVerifier,
};

#[derive(Parser, Debug)]
#[command(bin_name = "ib_oneshot_check")]
#[command(name = "IB oneshot EC checker")]
#[command(version = "0.1.0")]
#[command(author = "Jian")]
#[command(about = "Verifies the IB network connectivity")]
#[command(
    after_help = "Example: ./ib_oneshot_check -t some/to/ibdiagnet2/ -r some/to/ibdiagnet2/far/ -p 'LH:1,LSLH:896,LSCSLH:1277696'"
)]
pub struct Cli {
    #[arg(
        short,
        long,
        help = "Directory to the topology files (output sections of ibdiagnet2.db_csv)"
    )]
    pub topology_dir: PathBuf,
    #[arg(short, long, help = "Directory to the route files (output sections of ibdiagnet2.far)")]
    pub route_dir: PathBuf,

    #[arg(
        short, 
        long, 
        value_delimiter = ',',
        num_args = 1..,
        help = "Expected exact path patterns and their count, valid symbols: L(leaf), S(spine), C(core), H(host)"
    )]
    pub pattern_count: Vec<PatternExpectation>,
}

#[derive(Debug, Clone, Parser)]
pub struct PatternExpectation {
    pattern: String,
    count: usize,
}

impl From<&str> for PatternExpectation {
    fn from(s: &str) -> Self {
        let mut parts = s.splitn(2, ':');
        let pattern = parts.next().unwrap().to_string();
        let count = parts.next().unwrap().parse().unwrap();
        PatternExpectation { pattern, count }
    }
}

pub type SharedVerifier<'p, ME> = Arc<SnapshotVerifier<'p, ME>>;

pub fn build_verifier<'p, ME: MatchEncoder<'p>>(
    cli: Cli,
    engine: &'p ME,
) -> SharedVerifier<'p, ME> {
    let dp_config = IbDataPlaneConfig {
        engine,
        topology_dir: cli.topology_dir.clone(),
        far_dir: cli.route_dir.clone(),
        label_fn: label_node_topo_type,
    };
    let mut verifier = SnapshotVerifier::new(&dp_config).unwrap();
    // INFO: L: Leaf switch, S: Spine switch, C: Core switch, H: Host
    let plugin = SimplePathExactRegexSetPlugin::new(
        "Simple path count",
        cli.pattern_count.into_iter().map(|p| (p.pattern, p.count)).collect::<Vec<_>>(),
    );
    verifier.register_plugin(plugin.clone_boxed());
    verifier.refresh().unwrap();
    Arc::new(verifier)
}
