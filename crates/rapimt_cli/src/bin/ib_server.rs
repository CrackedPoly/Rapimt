use std::sync::{Arc, LazyLock};

use axum::{routing::get, Router};
use clap::Parser;
use rapimt_cli::ib::{
    build_verifier,
    server::{get_alerts, get_dag_from_handler, get_num_ec_handler},
    Cli,
};

use rapimt_core::r#match::engine::OxiddPredicateEngine;

static ENGINE: LazyLock<Arc<OxiddPredicateEngine>> =
    LazyLock::new(|| Arc::new(OxiddPredicateEngine::init(10000, 5000)));

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    println!("{:?}", cli);
    let verifier = build_verifier(cli, ENGINE.as_ref());

    // build our application with a single route
    let routes = Router::new()
        // GET /api/v1/num_ec
        .route("/api/v1/num_ec", get(get_num_ec_handler))
        // GET /api/v1/alert
        .route("/api/v1/alert", get(get_alerts))
        // GET /api/v1/dag/10593 or
        // GET /api/v1/dag/10593?source=11567708961049485322
        // lid: integer, source: guid as integer
        .route("/api/v1/dag/{lid}", get(get_dag_from_handler))
        .with_state(verifier);
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, routes).await.unwrap();
}
