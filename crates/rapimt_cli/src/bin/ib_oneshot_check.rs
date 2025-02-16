use clap::Parser;
use rapimt_cli::ib::{build_verifier, Cli};
use rapimt_core::r#match::engine::RuddyPredicateEngine;
use rapimt_ver::SnapshotQuery;

fn main() {
    let cli = Cli::parse();
    println!("{:?}", cli);
    let engine = RuddyPredicateEngine::init(10000, 5000);
    let verifier = build_verifier(cli, &engine);

    println!("#EC: {}", verifier.query_num_ec());
}
