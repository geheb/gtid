use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::{get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use gtid_shared::AppStateCore;
use gtid_shared::middleware;

use crate::handlers;

pub fn build_api_router(core: Arc<AppStateCore>) -> Router {
    let cors_layer = build_cors_layer(&core.config.cors_allowed_origins);
    let body_limit = core.config.max_request_body_bytes;

    Router::new()
        .route(
            "/",
            get(|| async {
                axum::response::Html(
                    r#"
<!doctype html>
<html lang="en">
<head><title>GT Id</title></head>
<body>
<pre>
  ___________________ .___    .___
 /  _____/\__    ___/ |   | __| _/
/   \  ___  |    |    |   |/ __ |
\    \_\  \ |    |    |   / /_/ |
 \______  / |____|    |___\____ |
        \/                     \/
</pre>
</body>
</html>
"#,
                )
            }),
        )
        .route("/health", get(|| async { "ok" }))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::well_known::openid_configuration),
        )
        .route("/jwks", get(handlers::jwks::jwks))
        .route("/token", post(handlers::token::token))
        .route("/userinfo", get(handlers::userinfo::userinfo))
        .route("/authorize-url", get(handlers::authorize_url::authorize_url))
        .route("/revoke", post(handlers::revoke::revoke))
        .route("/introspect", post(handlers::introspect::introspect))
        .fallback({
            let st = core.clone();
            move |conn: ConnectInfo<SocketAddr>, req: axum::http::Request<axum::body::Body>| {
                middleware::bot_trap::bot_trap_fallback(st.clone(), conn, req)
            }
        })
        .layer(axum::middleware::from_fn(
            middleware::content_type::validate_content_type,
        ))
        .layer(cors_layer)
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(axum::middleware::from_fn(
            middleware::security_headers::api_security_headers,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            core.clone(),
            middleware::bot_trap::bot_trap_guard,
        ))
        .with_state(core)
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::{Method, header};

    let origins = if allowed_origins.is_empty() {
        AllowOrigin::list(std::iter::empty::<axum::http::HeaderValue>())
    } else {
        AllowOrigin::list(
            allowed_origins
                .iter()
                .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok()),
        )
    };

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(3600))
}
