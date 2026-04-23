//! UI crate: HTML handlers, templates, static assets, and the UI router.
//!
//! Depends on [`gtid_shared::AppStateCore`] for shared state (DB repos, crypto keys,
//! config, rate limiters) and adds UI-only concerns on top (`tera::Tera`, asset
//! hashes, CSP cache).

pub mod ctx;
pub mod handlers;
pub mod middleware;
mod router;

pub use router::build_ui_router;

use std::sync::Arc;

use gtid_shared::AppStateCore;
use gtid_shared::middleware::lockout::AccountLockout;
use gtid_shared::middleware::pending_2fa::Pending2faStore;
use gtid_shared::middleware::pending_redirect::PendingRedirectStore;
use gtid_shared::repositories::trusted_device::TrustedDeviceRepository;

/// UI state — wraps [`AppStateCore`] and adds UI-only concerns:
/// template engine, localization, CSP cache, and stores that the stateless
/// API never touches (pending redirects, pending 2fa, account lockout,
/// trusted devices).
#[derive(Clone)]
pub struct AppState {
    pub core: Arc<AppStateCore>,
    pub tera: tera::Tera,
    pub locales: gtid_shared::i18n::Locales,
    pub css_hash: String,
    pub js_hash: String,
    pub csp: Arc<std::sync::RwLock<String>>,
    pub trusted_devices: TrustedDeviceRepository,
    pub account_lockout: AccountLockout,
    pub pending_redirects: PendingRedirectStore,
    pub pending_2fa: Pending2faStore,
}

// Forwards `state.users` etc. to the core for ergonomic access in UI handlers.
impl std::ops::Deref for AppState {
    type Target = AppStateCore;
    fn deref(&self) -> &AppStateCore {
        &self.core
    }
}

/// Loads all embedded HTML templates into a [`tera::Tera`] instance.
///
/// `include_str!` paths are resolved relative to this file, which is why the
/// function lives in this crate alongside `../static/`.
pub fn load_templates() -> tera::Tera {
    let mut tera = tera::Tera::default();
    tera.add_raw_templates(vec![
        ("base.html", include_str!("../static/base.html")),
        ("login.html", include_str!("../static/login.html")),
        ("authorize.html", include_str!("../static/authorize.html")),
        ("error.html", include_str!("../static/error.html")),
        ("admin/_sidebar.html", include_str!("../static/admin/_sidebar.html")),
        ("admin/dashboard.html", include_str!("../static/admin/dashboard.html")),
        ("admin/users.html", include_str!("../static/admin/users.html")),
        (
            "admin/user_create.html",
            include_str!("../static/admin/user_create.html"),
        ),
        ("admin/user_edit.html", include_str!("../static/admin/user_edit.html")),
        (
            "admin/email_templates.html",
            include_str!("../static/admin/email_templates.html"),
        ),
        (
            "admin/email_template_edit.html",
            include_str!("../static/admin/email_template_edit.html"),
        ),
        ("profile.html", include_str!("../static/profile.html")),
        ("admin/clients.html", include_str!("../static/admin/clients.html")),
        (
            "admin/client_create.html",
            include_str!("../static/admin/client_create.html"),
        ),
        (
            "admin/client_edit.html",
            include_str!("../static/admin/client_edit.html"),
        ),
        ("legal.html", include_str!("../static/legal.html")),
        (
            "admin/legal_pages.html",
            include_str!("../static/admin/legal_pages.html"),
        ),
        (
            "admin/legal_page_edit.html",
            include_str!("../static/admin/legal_page_edit.html"),
        ),
        ("setup.html", include_str!("../static/setup.html")),
        (
            "confirm_email_success.html",
            include_str!("../static/confirm_email_success.html"),
        ),
        (
            "confirm_email_change_success.html",
            include_str!("../static/confirm_email_change_success.html"),
        ),
        ("forgot_password.html", include_str!("../static/forgot_password.html")),
        (
            "forgot_password_sent.html",
            include_str!("../static/forgot_password_sent.html"),
        ),
        ("reset_password.html", include_str!("../static/reset_password.html")),
        (
            "reset_password_success.html",
            include_str!("../static/reset_password_success.html"),
        ),
        ("totp_setup.html", include_str!("../static/totp_setup.html")),
        ("totp_verify.html", include_str!("../static/totp_verify.html")),
    ])
    .expect("Failed to load embedded templates");
    tera
}
