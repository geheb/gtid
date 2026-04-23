// scope: shared — applied to both API and UI routers (validate_content_type layer)
use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn validate_content_type(request: Request<Body>, next: Next) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }

    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mime = content_type.split(';').next().unwrap_or("").trim().to_lowercase();

    if mime == "application/x-www-form-urlencoded" || mime == "application/json" {
        return next.run(request).await;
    }

    (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unsupported Content-Type").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }).post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(validate_content_type))
    }

    async fn run(method: Method, content_type: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().method(method).uri("/test");
        if let Some(ct) = content_type {
            builder = builder.header(header::CONTENT_TYPE, ct);
        }
        let request = builder.body(Body::empty()).unwrap();
        app().oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn get_passes_without_content_type() {
        assert_eq!(run(Method::GET, None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn post_form_urlencoded() {
        assert_eq!(
            run(Method::POST, Some("application/x-www-form-urlencoded")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn post_json() {
        assert_eq!(run(Method::POST, Some("application/json")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn post_json_with_charset() {
        assert_eq!(
            run(Method::POST, Some("application/json; charset=utf-8")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn post_missing_content_type() {
        assert_eq!(run(Method::POST, None).await, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn post_text_plain_rejected() {
        assert_eq!(
            run(Method::POST, Some("text/plain")).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[tokio::test]
    async fn post_multipart_rejected() {
        assert_eq!(
            run(Method::POST, Some("multipart/form-data")).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }
}
