use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Complete OIDC Authorization Code Flow with PKCE (Steps 0-10)
#[tokio::test]
async fn oidc_complete_flow() {
    let server = TestServer::start().await;
    let client = server.new_following_client();

    // ── Step 0: Setup - Create test client via admin panel ──
    setup_test_client(&server, &client).await;

    // ── Step 1: Discovery ──
    let disc: serde_json::Value = server
        .client
        .get(server.api_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(disc["issuer"].as_str().is_some(), "issuer missing");
    assert!(
        disc["authorization_endpoint"].as_str().is_some(),
        "authorization_endpoint missing"
    );
    assert!(disc["token_endpoint"].as_str().is_some(), "token_endpoint missing");
    assert!(disc["jwks_uri"].as_str().is_some(), "jwks_uri missing");

    // ── Step 2: JWKS ──
    let jwks: serde_json::Value = server
        .client
        .get(server.api_url("/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(jwks["keys"][0]["kty"].as_str().is_some(), "kty missing");
    assert!(jwks["keys"][0]["crv"].as_str().is_some(), "crv missing");

    // ── Step 3: Authorize URL ──
    let auth_resp: serde_json::Value = client
        .get(server.api_url("/authorize-url?scope=openid%20email%20profile"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let authorize_url = auth_resp["authorize_url"].as_str().expect("authorize_url missing");
    let code_verifier = auth_resp["code_verifier"].as_str().expect("code_verifier missing");
    assert!(!authorize_url.is_empty());
    assert!(!code_verifier.is_empty());

    // ── Step 4: Login ──
    // Use a no-redirect client for login flow to check redirects manually
    let login_client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("E2ETest/1.0")
        .build()
        .unwrap();

    let login_page = login_client
        .get(server.ui_url("/login"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let csrf = extract_csrf(&login_page).expect("CSRF token missing on login page");
    assert!(!csrf.is_empty(), "CSRF token empty");

    let login_resp = login_client
        .post(server.ui_url("/login"))
        .form(&[
            ("email", ADMIN_EMAIL),
            ("password", ADMIN_PASSWORD),
            ("csrf_token", csrf.as_str()),
            ("redirect", ""),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(login_resp.status(), 303, "Login should redirect with 303");

    // ── Step 4b: Complete 2FA ──
    let location = login_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.contains("/2fa/verify"),
        "Admin login should redirect to 2FA verify"
    );
    complete_2fa_verify(&server, &login_client, &location).await;

    // ── Step 5: Consent ──
    let consent_resp = login_client.get(authorize_url).send().await.unwrap();

    let auth_code;
    if let Some(location) = consent_resp.headers().get("location") {
        // Auto-redirect (consent already given)
        let loc_str = location.to_str().unwrap();
        let url = url::Url::parse(loc_str).unwrap();
        auth_code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .expect("No code in auto-redirect")
            .1
            .to_string();
    } else {
        // Consent page shown - extract form fields and submit
        let consent_html = consent_resp.text().await.unwrap();
        let consent_csrf = extract_csrf(&consent_html).expect("Consent CSRF missing");
        let form_client_id = extract_input_value(&consent_html, "client_id").unwrap_or_default();
        let form_redirect_uri = extract_input_value(&consent_html, "redirect_uri").unwrap_or_default();
        let form_scope = extract_input_value(&consent_html, "scope").unwrap_or_default();
        let form_state = extract_input_value(&consent_html, "state").unwrap_or_default();
        let form_code_challenge = extract_input_value(&consent_html, "code_challenge").unwrap_or_default();
        let form_code_challenge_method =
            extract_input_value(&consent_html, "code_challenge_method").unwrap_or_default();
        let form_nonce = extract_input_value(&consent_html, "nonce").unwrap_or_default();
        let form_response_type = extract_input_value(&consent_html, "response_type").unwrap_or("code".to_string());

        let consent_submit = login_client
            .post(server.ui_url("/authorize"))
            .form(&[
                ("response_type", form_response_type.as_str()),
                ("client_id", form_client_id.as_str()),
                ("redirect_uri", form_redirect_uri.as_str()),
                ("scope", form_scope.as_str()),
                ("state", form_state.as_str()),
                ("code_challenge", form_code_challenge.as_str()),
                ("code_challenge_method", form_code_challenge_method.as_str()),
                ("nonce", form_nonce.as_str()),
                ("consent", "allow"),
                ("csrf_token", consent_csrf.as_str()),
            ])
            .send()
            .await
            .unwrap();

        let location = consent_submit
            .headers()
            .get("location")
            .expect("No redirect after consent")
            .to_str()
            .unwrap();

        let url = url::Url::parse(location).unwrap();
        auth_code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .expect("No code in consent redirect")
            .1
            .to_string();
    };

    assert!(!auth_code.is_empty(), "Auth code empty");

    // ── Step 6: Token Exchange ──
    let token_resp: serde_json::Value = login_client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", auth_code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let access_token = token_resp["access_token"].as_str().expect("access_token missing");
    let id_token = token_resp["id_token"].as_str().expect("id_token missing");
    let refresh_token = token_resp["refresh_token"].as_str().expect("refresh_token missing");
    assert!(token_resp["token_type"].as_str().is_some(), "token_type missing");
    assert!(token_resp["expires_in"].as_i64().is_some(), "expires_in missing");

    // ── Step 7: ID Token Payload ──
    let payload_b64 = id_token.split('.').nth(1).expect("Invalid JWT");
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).expect("Invalid base64url");
    let id_payload: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("Invalid JSON payload");

    assert!(id_payload["sub"].as_str().is_some(), "sub missing");
    assert!(id_payload["email"].as_str().is_some(), "email missing");
    assert!(id_payload["iss"].as_str().is_some(), "iss missing");
    assert!(id_payload["aud"].as_str().is_some(), "aud missing");
    assert!(id_payload["nonce"].as_str().is_some(), "nonce missing");

    // ── Step 8: Userinfo ──
    let userinfo: serde_json::Value = login_client
        .get(server.api_url("/userinfo"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(userinfo["sub"].as_str().is_some(), "userinfo sub missing");
    assert!(userinfo["email"].as_str().is_some(), "userinfo email missing");

    // ── Step 9: Token Refresh ──
    let refresh_resp: serde_json::Value = login_client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let new_access = refresh_resp["access_token"].as_str().expect("New access_token missing");
    let new_refresh = refresh_resp["refresh_token"]
        .as_str()
        .expect("New refresh_token missing");
    assert_ne!(new_refresh, refresh_token, "Refresh token was not rotated");
    assert!(!new_access.is_empty());

    // ── Step 10: Token Revocation (RFC 7009) ──
    let revoke_status = login_client
        .post(server.api_url("/revoke"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[("token", new_refresh), ("token_type_hint", "refresh_token")])
        .send()
        .await
        .unwrap()
        .status();

    assert_eq!(revoke_status, 200, "Revoke endpoint failed");

    // Verify revoked token is rejected
    let revoked_resp = login_client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_refresh),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap();

    assert_ne!(revoked_resp.status(), 200, "Revoked token should be rejected");
}
