use axum::{extract::State, response::{Html, IntoResponse, Response}};
use std::sync::Arc;
use tera::Context;

use crate::errors::AppError;
use crate::middleware::csrf::CsrfToken;
use crate::middleware::language::Lang;
use crate::middleware::session::AdminUser;
use crate::routes::ctx::DashboardCtx;
use crate::AppState;

pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let users = state.users.list().await?;
    let active_users = state.sessions.count_active_users().await.unwrap_or(0);
    let locked_users = state.account_lockout.locked_count();
    let pending_emails = state.email_queue.count_pending().await.unwrap_or(0);
    let unconfirmed_users = users.iter().filter(|u| !u.is_confirmed).count();
    let ctx = Context::from_serialize(DashboardCtx {
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "dashboard",
        csrf_token: &csrf.form_token,
        user_count: users.len(),
        active_users,
        locked_users,
        pending_emails,
        unconfirmed_users,
    })?;
    let rendered = state.tera.render("admin/dashboard.html", &ctx)?;
    Ok(Html(rendered).into_response())
}
