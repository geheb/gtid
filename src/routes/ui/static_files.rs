use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

const CSS_CONTENT: &str = include_str!("../../../static/style.css");
const JS_CONTENT: &str = include_str!("../../../static/app.js");
const QUILL_JS: &str = include_str!("../../../static/lib/quill/quill.js");
const QUILL_CSS: &str = include_str!("../../../static/lib/quill/quill.snow.css");
const EMAIL_EDITOR_JS: &str = include_str!("../../../static/email_editor.js");

struct StaticFile {
    content: &'static str,
    content_type: &'static str,
}

fn lookup(path: &str) -> Option<StaticFile> {
    match path {
        "style.css" => Some(StaticFile {
            content: CSS_CONTENT,
            content_type: "text/css; charset=utf-8",
        }),
        "app.js" => Some(StaticFile {
            content: JS_CONTENT,
            content_type: "application/javascript; charset=utf-8",
        }),
        "lib/quill/quill.js" => Some(StaticFile {
            content: QUILL_JS,
            content_type: "application/javascript; charset=utf-8",
        }),
        "lib/quill/quill.snow.css" => Some(StaticFile {
            content: QUILL_CSS,
            content_type: "text/css; charset=utf-8",
        }),
        "email_editor.js" => Some(StaticFile {
            content: EMAIL_EDITOR_JS,
            content_type: "application/javascript; charset=utf-8",
        }),
        _ => None,
    }
}

pub async fn serve(Path(path): Path<String>) -> Response {
    match lookup(&path) {
        Some(file) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, file.content_type),
                (header::CACHE_CONTROL, "public, max-age=604800, immutable"),
            ],
            file.content,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn short_hash(content: &str) -> String {
    let hash = Sha256::digest(content.as_bytes());
    hex::encode(&hash[..8])
}

/// Returns (css_hash, js_hash) for cache-busting query strings.
pub fn asset_hashes() -> (String, String) {
    (short_hash(CSS_CONTENT), short_hash(JS_CONTENT))
}

/// Returns (quill_js_hash, quill_css_hash, editor_js_hash) for email editor assets.
pub fn email_editor_hashes() -> (String, String, String) {
    (
        short_hash(QUILL_JS),
        short_hash(QUILL_CSS),
        short_hash(EMAIL_EDITOR_JS),
    )
}
