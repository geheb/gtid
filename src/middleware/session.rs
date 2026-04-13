use axum::{extract::FromRequestParts, http::request::Parts, response::Response};
use std::sync::Arc;
use tower_cookies::Cookies;

use crate::errors::AppError;
use crate::models::user::User;
use crate::routes::ui::redirect;

// Cookies
pub const SESSION_ID_COOKIE_NAME: &str = "__s";
pub const TRUST_DEVICE_COOKIE_NAME: &str = "__td";

fn login_redirect() -> Response {
    redirect("/login")
}

/// Extracts the current session user from the session cookie.
/// Redirects to /login if no valid session exists.
pub struct SessionUser(pub User);

impl FromRequestParts<Arc<crate::AppState>> for SessionUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| login_redirect())?;

        let session_id = cookies
            .get(SESSION_ID_COOKIE_NAME)
            .map(|c| c.value().to_string())
            .ok_or_else(login_redirect)?;

        let session = state
            .sessions
            .find_valid(&session_id)
            .await
            .map_err(|_| login_redirect())?
            .ok_or_else(login_redirect)?;

        let user = state
            .users
            .find_by_id(&session.user_id)
            .await
            .map_err(|_| login_redirect())?
            .ok_or_else(login_redirect)?;

        Ok(SessionUser(user))
    }
}

/// Optionally extracts a session user (returns None if not logged in).
pub struct OptionalSessionUser(pub Option<User>);

impl FromRequestParts<Arc<crate::AppState>> for OptionalSessionUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|e| AppError::Internal(format!("Cookie layer missing: {}", e.1)))?;

        let session_id = match cookies.get(SESSION_ID_COOKIE_NAME) {
            Some(c) => c.value().to_string(),
            None => return Ok(OptionalSessionUser(None)),
        };

        let session = match state.sessions.find_valid(&session_id).await? {
            Some(s) => s,
            None => return Ok(OptionalSessionUser(None)),
        };

        let user = state.users.find_by_id(&session.user_id).await?;
        Ok(OptionalSessionUser(user))
    }
}

/// Admin-only session extractor. Redirects to /login if not logged in or not admin.
pub struct AdminUser(#[allow(dead_code)] pub User);

impl FromRequestParts<Arc<crate::AppState>> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let SessionUser(user) = SessionUser::from_request_parts(parts, state).await?;
        if !user.is_admin() {
            return Err(login_redirect());
        }
        // Defense-in-depth: admin must have 2FA configured
        if !user.has_totp() {
            return Err(login_redirect());
        }
        Ok(AdminUser(user))
    }
}
