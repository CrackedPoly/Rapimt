use axum::{
    extract::{Path, Query, State},
    Json,
};
use rapimt_core::r#match::engine::OxiddPredicateEngine;
use rapimt_io::ib::loader::{Guid, Lid};
use rapimt_ver::SnapshotQuery;
use serde::{Deserialize, Serialize};

use super::SharedVerifier;

#[derive(Serialize)]
pub struct ResponseTemplate<'a, T: Serialize> {
    code: isize,
    message: &'a str,
    data: T,
}

impl<'a, T: Serialize> ResponseTemplate<'a, T> {
    fn new(code: isize, message: &'a str, data: T) -> Self {
        Self {
            code,
            message,
            data,
        }
    }
}

#[derive(Deserialize)]
pub struct DagFromQueryParams {
    source: Option<Guid>,
}

#[axum::debug_handler]
pub async fn get_dag_from_handler(
    State(state): State<SharedVerifier<'static, OxiddPredicateEngine>>,
    Path(lid): Path<Lid>,
    Query(params): Query<DagFromQueryParams>,
) -> Json<ResponseTemplate<'static, impl Serialize>> {
    if let Some(links) = match params.source {
        Some(src) => state.query_dag_from(lid, src),
        None => state.query_dag(lid),
    } {
        Json(ResponseTemplate::new(0, "Success", links))
    } else {
        Json(ResponseTemplate::new(-1, "Not found", vec![]))
    }
}

pub async fn get_num_ec_handler(
    State(state): State<SharedVerifier<'static, OxiddPredicateEngine>>,
) -> Json<ResponseTemplate<'static, impl Serialize>> {
    Json(ResponseTemplate::new(0, "Success", state.query_num_ec()))
}

pub async fn get_alerts(
    State(state): State<SharedVerifier<'static, OxiddPredicateEngine>>,
) -> Json<ResponseTemplate<'static, impl Serialize>> {
    Json(ResponseTemplate::new(0, "Success", state.list_alert()))
}
