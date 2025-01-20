use axum::{routing::get, Router};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "IB oneshot EC checker")]
#[command(version = "0.1.0")]
#[command(about = "Verifies the IB network connectivity")]
struct Cli {
    #[arg(
        short,
        long,
        help = "Directory to the topology files (output sections of ibdiagnet2)"
    )]
    pub topology_dir: PathBuf,
    #[arg(short, long, help = "Directory to the route files (output of ibroute)")]
    pub route_dir: PathBuf,

    // list of checks to perform
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    pub checks: Vec<CheckOption>,
}

#[derive(Debug, Clone, Copy, Parser)]
pub enum CheckOption {
    NumEc,
    LongestPath,
}

impl From<&str> for CheckOption {
    fn from(s: &str) -> Self {
        match s {
            "numec" => CheckOption::NumEc,
            "longestpath" => CheckOption::LongestPath,
            _ => panic!("Unknown check: {}", s),
        }
    }
}

#[tokio::main]
async fn main() {
    let _ = Cli::parse();
    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/fib/{id}", get("Hello, World!"));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
