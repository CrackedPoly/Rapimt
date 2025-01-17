use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "IB OneShot verifier")]
#[command(version = "0.1.0")]
#[command(about = "Verifies the IB network connectivity")]
struct Cli {
    #[arg(short, long, help = "Path to the nodes.csv file")]
    nodes_csv: PathBuf,

    #[arg(short, long, help = "Path to the ports.csv file")]
    ports_csv: PathBuf,

    #[arg(short, long, help = "Path to the links.csv file")]
    links_csv: PathBuf,

    #[arg(short, long, help = "Path to the .far file")]
    far_file: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Compute the number of EC
    Ecnum,

    /// Get the EC with the longest path
    Longest,
}

fn main() {
    let _ = Cli::parse();
}
