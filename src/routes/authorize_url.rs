use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::crypto::{id::new_id, pkce::generate_pkce};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct AuthorizeUrlParams {
    pub client_id: String,
    pub scope: Option<String>,
}

pub async fn authorize_url(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeUrlParams>,
) -> Result<Response, Response> {
    let scope = params.scope.as_deref().unwrap_or("openid+email+profile");
    tracing::info!("Calling authorize-url client_id={} scope={} ...", params.client_id, scope);

    let client = state.clients.find_by_id(&params.client_id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response())?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Unknown client_id"}))).into_response())?;

    let (code_verifier, code_challenge) = generate_pkce();
    let state_param = new_id();
    let nonce = new_id();

    let authorize_url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
        state.config.public_ui_uri,
        super::urlencoding(&client.client_id),
        super::urlencoding(&client.client_redirect_uri),
        super::urlencoding(scope),
        super::urlencoding(&state_param),
        super::urlencoding(&code_challenge),
        super::urlencoding(&nonce),
    );

    Ok(Json(serde_json::json!({
        "authorize_url": authorize_url,
        "code_verifier": code_verifier
    })).into_response())
}
