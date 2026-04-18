use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use std::sync::Arc;

use crate::AppStateCore;

pub async fn openid_configuration(State(state): State<Arc<AppStateCore>>) -> impl IntoResponse {
    tracing::info!("Calling openid-configuration ...");

    let issuer = &state.config.issuer_uri;
    let ui = &state.config.public_ui_uri;
    let config = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{ui}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": crate::routes::api::SUPPORTED_SCOPES,
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "end_session_endpoint": format!("{ui}/logout"),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"]
    });

    ([(header::CACHE_CONTROL, "no-cache, no-store")], Json(config))
}
