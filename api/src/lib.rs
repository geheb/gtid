//! HTTP API for the GT Id OAuth2/OIDC server (token, userinfo, jwks, etc.).
//!
//! Entry point is [`build_api_router`], which returns a fully-layered
//! `axum::Router` ready to serve.

mod handlers;
mod helpers;
mod router;

pub use router::build_api_router;
