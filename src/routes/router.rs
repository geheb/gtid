use axum::{routing::get, Router};
use std::sync::Arc;

use crate::AppState;

use super::{api, ui};

pub fn build_api_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(|| async {
            axum::response::Html(r#"
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
"#)
        }))
        .route("/health", get(|| async { "ok" }))
        .route(
            "/.well-known/openid-configuration",
            get(api::well_known::openid_configuration),
        )
        .route("/jwks", get(api::jwks::jwks))
        .route("/token", axum::routing::post(api::token::token))
        .route("/userinfo", get(api::userinfo::userinfo))
        .route("/authorize-url", get(api::authorize_url::authorize_url))
        .route("/revoke", axum::routing::post(api::revoke::revoke))
        .route("/introspect", axum::routing::post(api::introspect::introspect))
}

pub fn build_ui_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(ui::root_redirect))
        .route("/setup", get(ui::setup_form).post(ui::setup_submit))
        .route("/static/{*path}", get(ui::static_files::serve))
        .route("/login", get(api::auth::login_page).post(api::auth::login_submit))
        .route("/logout", axum::routing::post(api::auth::logout).get(api::auth::rp_initiated_logout))
        .route(
            "/authorize",
            get(api::authorize::authorize_get).post(api::authorize::authorize_post),
        )
        .route("/profile", get(api::profile::profile_page).post(api::profile::profile_submit))
        .route("/profile/password", axum::routing::post(api::profile::password_submit))
        .route("/admin", get(ui::dashboard))
        .route("/admin/clients", get(ui::clients_list))
        .route(
            "/admin/clients/create",
            get(ui::client_create_form).post(ui::client_create_submit),
        )
        .route(
            "/admin/clients/{id}/edit",
            get(ui::client_edit_form).post(ui::client_edit_submit),
        )
        .route("/admin/clients/{id}/delete", axum::routing::post(ui::client_delete))
        .route("/admin/users", get(ui::users_list))
        .route(
            "/admin/users/create",
            get(ui::user_create_form).post(ui::user_create_submit),
        )
        .route(
            "/admin/users/{id}/edit",
            get(ui::user_edit_form).post(ui::user_edit_submit),
        )
        .route("/admin/users/{id}/delete", axum::routing::post(ui::user_delete))
        .route("/favicon.ico", get(ui::static_files::favicon_ico))
        .route("/favicon.svg", get(ui::static_files::favicon_svg))
        .route("/apple-touch-icon.png", get(ui::static_files::apple_touch_icon))
        .route("/apple-touch-icon-precomposed.png", get(ui::static_files::apple_touch_icon_precomposed))
        .route("/imprint", get(ui::legal::imprint))
        .route("/privacy", get(ui::legal::privacy))
        .route("/admin/email-templates", get(ui::email_templates_list))
        .route(
            "/admin/email-templates/{template_type}/edit",
            get(ui::email_template_edit_form).post(ui::email_template_edit_submit),
        )
        .route("/admin/legal-pages", get(ui::legal_pages_list))
        .route(
            "/admin/legal-pages/{page_type}/edit",
            get(ui::legal_page_edit_form).post(ui::legal_page_edit_submit),
        )
}
