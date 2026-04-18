use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use std::sync::Arc;

use crate::AppStateCore;

pub async fn jwks(State(state): State<Arc<AppStateCore>>) -> impl IntoResponse {
    tracing::info!("Calling jwks ...");

    (
        [(header::CACHE_CONTROL, "no-cache, no-store")],
        Json(state.key_store.jwks_json()),
    )
}
