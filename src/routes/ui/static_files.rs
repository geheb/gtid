use axum::{
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

const CSS_CONTENT: &str = include_str!("../../../static/style.css");
const JS_CONTENT: &str = include_str!("../../../static/app.js");
const QUILL_JS: &str = include_str!("../../../static/lib/quill/quill.js");
const QUILL_CSS: &str = include_str!("../../../static/lib/quill/quill.snow.css");
const EMAIL_EDITOR_JS: &str = include_str!("../../../static/email_editor.js");
const FAVICON_ICO: &[u8] = include_bytes!("../../../static/favicon.ico");
const FAVICON_SVG: &str = include_str!("../../../static/favicon.svg");
const APPLE_TOUCH_ICON: &[u8] = include_bytes!("../../../static/apple-touch-icon.png");
const APPLE_TOUCH_ICON_PRE: &[u8] = include_bytes!("../../../static/apple-touch-icon-precomposed.png");
const ANIMATED_WAVE: &[u8] = include_bytes!("../../../static/animated-wave.svg");
const WAVE: &[u8] = include_bytes!("../../../static/wave.svg");

enum StaticContent {
    Text(&'static str),
    Binary(&'static [u8]),
}

struct StaticFile {
    content: StaticContent,
    content_type: &'static str,
}

fn lookup(path: &str) -> Option<StaticFile> {
    match path {
        "style.css" => Some(StaticFile {
            content: StaticContent::Text(CSS_CONTENT),
            content_type: "text/css; charset=utf-8",
        }),
        "app.js" => Some(StaticFile {
            content: StaticContent::Text(JS_CONTENT),
            content_type: "application/javascript; charset=utf-8",
        }),
        "lib/quill/quill.js" => Some(StaticFile {
            content: StaticContent::Text(QUILL_JS),
            content_type: "application/javascript; charset=utf-8",
        }),
        "lib/quill/quill.snow.css" => Some(StaticFile {
            content: StaticContent::Text(QUILL_CSS),
            content_type: "text/css; charset=utf-8",
        }),
        "email_editor.js" => Some(StaticFile {
            content: StaticContent::Text(EMAIL_EDITOR_JS),
            content_type: "application/javascript; charset=utf-8",
        }),
        "favicon.ico" => Some(StaticFile {
            content: StaticContent::Binary(FAVICON_ICO),
            content_type: "image/x-icon",
        }),
        "favicon.svg" => Some(StaticFile {
            content: StaticContent::Text(FAVICON_SVG),
            content_type: "image/svg+xml",
        }),
        "apple-touch-icon.png" => Some(StaticFile {
            content: StaticContent::Binary(APPLE_TOUCH_ICON),
            content_type: "image/png",
        }),
        "apple-touch-icon-precomposed.png" => Some(StaticFile {
            content: StaticContent::Binary(APPLE_TOUCH_ICON_PRE),
            content_type: "image/png",
        }),
        "animated-wave.svg" => Some(StaticFile {
            content: StaticContent::Binary(ANIMATED_WAVE),
            content_type: "image/svg+xml",
        }),
        "wave.svg" => Some(StaticFile {
            content: StaticContent::Binary(WAVE),
            content_type: "image/svg+xml",
        }),
        _ => None,
    }
}

pub async fn serve(Path(path): Path<String>) -> Response {
    match lookup(&path) {
        Some(file) => {
            let headers = [
                (header::CONTENT_TYPE, file.content_type),
                (header::CACHE_CONTROL, "public, max-age=604800, immutable"),
            ];
            match file.content {
                StaticContent::Text(text) => (StatusCode::OK, headers, text).into_response(),
                StaticContent::Binary(bytes) => (StatusCode::OK, headers, bytes).into_response(),
            }
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn favicon_ico() -> Response {
    serve(Path("favicon.ico".to_string())).await
}

pub async fn favicon_svg() -> Response {
    serve(Path("favicon.svg".to_string())).await
}

pub async fn apple_touch_icon() -> Response {
    serve(Path("apple-touch-icon.png".to_string())).await
}

pub async fn apple_touch_icon_precomposed() -> Response {
    serve(Path("apple-touch-icon-precomposed.png".to_string())).await
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
    (short_hash(QUILL_JS), short_hash(QUILL_CSS), short_hash(EMAIL_EDITOR_JS))
}
