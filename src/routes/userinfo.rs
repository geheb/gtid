use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::crypto::jwt;
use crate::AppState;

pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Response> {
    tracing::info!("Calling userinfo ...");

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing_token"})),
            )
                .into_response()
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response()
    })?;

    // #6: Try all available keys (current + previous) for verification
    // Decode without audience validation first, then verify client exists
    let decoding_keys = state.key_store.decoding_keys();
    let claims = {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&[&state.config.issuer_uri]);
        validation.validate_aud = false;
        let mut result = None;
        for key in &decoding_keys {
            match jsonwebtoken::decode::<jwt::AccessTokenClaims>(token, key, &validation) {
                Ok(data) => { result = Some(data.claims); break; }
                Err(_) => {}
            }
        }
        result.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
        })?
    };
    // Verify the client in the token's audience exists
    state.clients.find_by_id(&claims.aud).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "server_error"}))).into_response())?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_token"}))).into_response())?;

    let user = state
        .users
        .find_by_id(&claims.sub)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "user_not_found"})),
            )
                .into_response()
        })?;

    let mut response = serde_json::json!({
        "sub": user.id,
        "roles": user.roles(),
    });

    if claims.scope.contains("email") || claims.scope.contains("openid") {
        response["email"] = serde_json::json!(user.email);
    }
    if claims.scope.contains("profile") {
        if let Some(ref name) = user.display_name {
            response["name"] = serde_json::json!(name);
        }
    }

    tracing::info!("Return userinfo={}", response);

    Ok(Json(response).into_response())
}
