use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::redirect::Policy;

/// Shared test setup: starts server, creates client, logs in.
/// Returns server + a single logged-in client with initial consent given.
async fn setup() -> (TestServer, reqwest::Client) {
    let server = TestServer::start().await;

    let client = server.new_client();
    setup_test_client(&server, &client).await;

    // Give initial consent so get_fresh_code works (auto-redirect on subsequent calls)
    let auth_resp: serde_json::Value = client
        .get(server.api_url("/authorize-url?scope=openid%20email%20profile"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let authorize_url = auth_resp["authorize_url"].as_str().unwrap();
    let code_verifier = auth_resp["code_verifier"].as_str().unwrap();

    let consent_resp = client.get(authorize_url).send().await.unwrap();
    if consent_resp.headers().get("location").is_none() {
        // Need to submit consent form
        let consent_html = consent_resp.text().await.unwrap();
        let consent_csrf = extract_csrf(&consent_html).unwrap();
        let fields: Vec<(&str, String)> = [
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "response_type",
        ]
        .iter()
        .map(|name| (*name, extract_input_value(&consent_html, name).unwrap_or_default()))
        .collect();

        let mut form = fields.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>();
        form.push(("consent", "allow"));
        form.push(("csrf_token", consent_csrf.as_str()));

        let _ = client
            .post(server.ui_url("/authorize"))
            .form(&form)
            .send()
            .await
            .unwrap();
    } else {
        // Auto-consent - exchange code to establish token family
        let loc = consent_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let url = url::Url::parse(&loc).unwrap();
        let code = url.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
        let _ = exchange_code(&server, &client, &code, code_verifier).await;
    }

    (server, client)
}

/// Get a fresh code and exchange it for tokens.
async fn get_fresh_tokens(server: &TestServer, client: &reqwest::Client) -> serde_json::Value {
    let (code, verifier) = get_fresh_code(server, client).await;
    exchange_code(server, client, &code, &verifier).await
}

// ── Step 11: Hidden-Field Manipulation ──

#[tokio::test]
async fn hidden_field_manipulation() {
    let (server, client) = setup().await;

    // Get a CSRF token from profile page (user is logged in)
    let profile = client.get(server.ui_url("/profile")).send().await.unwrap();

    // Follow redirect if needed
    let profile_html = if profile.status() == 303 {
        let loc = profile.headers().get("location").unwrap().to_str().unwrap();
        let full_url = if loc.starts_with('/') {
            server.ui_url(loc)
        } else {
            loc.to_string()
        };
        client.get(&full_url).send().await.unwrap().text().await.unwrap()
    } else {
        profile.text().await.unwrap()
    };
    let csrf = extract_csrf(&profile_html).expect("No CSRF for security tests");

    // 11a: Manipulated redirect_uri -> must be 400
    let resp = client
        .post(server.ui_url("/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", "https://evil.example.com/steal"),
            ("scope", "openid"),
            ("state", "test"),
            ("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("code_challenge_method", "S256"),
            ("consent", "deny"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "11a: Manipulated redirect_uri not rejected");

    // 11b: Invalid scope -> must be 400
    let resp = client
        .post(server.ui_url("/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid admin root"),
            ("state", "test"),
            ("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("code_challenge_method", "S256"),
            ("consent", "allow"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "11b: Invalid scope not rejected");

    // 11c: Empty code_challenge -> must be 400
    let resp = client
        .post(server.ui_url("/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "test"),
            ("code_challenge", ""),
            ("code_challenge_method", "S256"),
            ("consent", "allow"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "11c: Empty code_challenge not rejected");

    // 11d: Oversized state (>1024 chars) -> must be 400
    let long_state = "A".repeat(1025);
    let resp = client
        .post(server.ui_url("/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", &long_state),
            ("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("code_challenge_method", "S256"),
            ("consent", "allow"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "11d: Oversized state not rejected");
}

// ── Step 12: Auth Code Replay ──

#[tokio::test]
async fn auth_code_replay() {
    let (server, client) = setup().await;

    let (code, verifier) = get_fresh_code(&server, &client).await;

    // First exchange - should succeed
    let first = exchange_code(&server, &client, &code, &verifier).await;
    assert!(first["access_token"].as_str().is_some(), "First exchange failed");

    // Replay - must fail
    let replay = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(replay.status(), 200, "Auth code replay was accepted");
}

// ── Step 13: PKCE Downgrade ──

#[tokio::test]
async fn pkce_downgrade() {
    let (server, client) = setup().await;

    // 13a: Authorize without code_challenge
    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123",
            CLIENT_ID, REDIRECT_URI
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "13a: Authorize without code_challenge not rejected");

    // 13b: code_challenge_method=plain
    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=plain",
            CLIENT_ID, REDIRECT_URI
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "13b: code_challenge_method=plain not rejected");
}

// ── Step 14: Wrong code_verifier ──

#[tokio::test]
async fn wrong_code_verifier() {
    let (server, client) = setup().await;

    let (code, _verifier) = get_fresh_code(&server, &client).await;

    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", "WRONG_VERIFIER_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "Wrong code_verifier was accepted");
}

// ── Step 15: redirect_uri Binding at Token Endpoint ──

#[tokio::test]
async fn redirect_uri_binding() {
    let (server, client) = setup().await;

    let (code, verifier) = get_fresh_code(&server, &client).await;

    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://evil.example.com/steal"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "Wrong redirect_uri was accepted at token endpoint");
}

// ── Step 16: Client Authentication ──

#[tokio::test]
async fn client_authentication() {
    let (server, client) = setup().await;

    // 16a: Without client_secret
    let (code, verifier) = get_fresh_code(&server, &client).await;
    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "16a: Token without client_secret accepted");

    // 16b: Wrong client_secret
    let (code2, verifier2) = get_fresh_code(&server, &client).await;
    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code2.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", "wrong-secret"),
            ("code_verifier", verifier2.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "16b: Wrong client_secret accepted");

    // 16c: Wrong client_id
    let (code3, verifier3) = get_fresh_code(&server, &client).await;
    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code3.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", "evil-app"),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", verifier3.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "16c: Wrong client_id accepted");
}

// ── Step 17: JWT Algorithm Validation ──

#[tokio::test]
async fn jwt_algorithm() {
    let (server, client) = setup().await;

    let tokens = get_fresh_tokens(&server, &client).await;
    let id_token = tokens["id_token"].as_str().unwrap();

    // Decode JWT header
    let header_b64 = id_token.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

    // 17a: Algorithm must be EdDSA
    assert_eq!(
        header["alg"].as_str().unwrap(),
        "EdDSA",
        "17a: JWT algorithm is not EdDSA"
    );

    // 17b: kid must exist in JWKS
    let kid = header["kid"].as_str().unwrap();
    let jwks: serde_json::Value = client
        .get(server.api_url("/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwks_kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|k| k["kid"].as_str())
        .collect();
    assert!(jwks_kids.contains(&kid), "17b: JWT kid not in JWKS");

    // 17c: Discovery only lists EdDSA
    let disc: serde_json::Value = client
        .get(server.api_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let algs: Vec<&str> = disc["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(algs, vec!["EdDSA"], "17c: Discovery lists unexpected algorithms");
}

// ── Step 18: Tampered JWT ──

#[tokio::test]
async fn tampered_jwt() {
    let (server, client) = setup().await;

    let tokens = get_fresh_tokens(&server, &client).await;
    let access_token = tokens["access_token"].as_str().unwrap();
    let parts: Vec<&str> = access_token.split('.').collect();
    let (header, payload, sig) = (parts[0], parts[1], parts[2]);

    // 18a: Modified payload (changed sub)
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
    let mut payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload_json["sub"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
    let tampered_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload_json).unwrap());
    let tampered_token = format!("{header}.{tampered_payload}.{sig}");

    let resp = client
        .get(server.api_url("/userinfo"))
        .header("Authorization", format!("Bearer {tampered_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "18a: Tampered JWT accepted");

    // 18b: Invalid signature
    let badsig_token = format!("{header}.{payload}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let resp = client
        .get(server.api_url("/userinfo"))
        .header("Authorization", format!("Bearer {badsig_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "18b: JWT with bad signature accepted");

    // 18c: alg=none
    let none_header = URL_SAFE_NO_PAD.encode(b"{\"typ\":\"JWT\",\"alg\":\"none\"}");
    let none_token = format!("{none_header}.{payload}.");
    let resp = client
        .get(server.api_url("/userinfo"))
        .header("Authorization", format!("Bearer {none_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "18c: JWT with alg=none accepted");

    // 18d: Empty Bearer token
    let resp = client
        .get(server.api_url("/userinfo"))
        .header("Authorization", "Bearer ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "18d: Empty bearer token accepted");
}

// ── Step 19: Missing User-Agent ──

#[tokio::test]
async fn missing_user_agent() {
    let (server, client) = setup().await;

    // Use the logged-in client but override User-Agent to empty
    let resp = client
        .post(server.ui_url("/authorize"))
        .header("User-Agent", "")
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "test"),
            ("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("code_challenge_method", "S256"),
            ("consent", "allow"),
            ("csrf_token", "dummy"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 418, "Request without User-Agent not rejected");
}

// ── Step 20: CSRF Validation ──

#[tokio::test]
async fn csrf_validation() {
    let (server, client) = setup().await;

    // 20a: Consent without CSRF token
    let resp = client
        .post(server.ui_url("/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "test"),
            ("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("code_challenge_method", "S256"),
            ("consent", "allow"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "20a: Consent without CSRF accepted");

    // 20b: Consent with wrong CSRF token
    let resp = client
        .post(server.ui_url("/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "test"),
            ("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("code_challenge_method", "S256"),
            ("consent", "allow"),
            (
                "csrf_token",
                "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa6666bbbb7777",
            ),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "20b: Consent with wrong CSRF accepted");
}

// ── Step 21: Security Headers ──

#[tokio::test]
async fn security_headers() {
    let (server, _client) = setup().await;

    let client = reqwest::Client::builder()
        .user_agent("E2ETest/1.0")
        .redirect(Policy::none())
        .build()
        .unwrap();

    let resp = client.get(server.ui_url("/login")).send().await.unwrap();
    let headers = resp.headers();

    // 21a: X-Content-Type-Options
    assert_eq!(
        headers.get("x-content-type-options").map(|v| v.to_str().unwrap()),
        Some("nosniff"),
        "21a: X-Content-Type-Options missing"
    );

    // 21b: X-Frame-Options
    let xfo = headers
        .get("x-frame-options")
        .map(|v| v.to_str().unwrap().to_uppercase());
    assert_eq!(xfo.as_deref(), Some("DENY"), "21b: X-Frame-Options missing/not DENY");

    // 21c: Content-Security-Policy
    assert!(
        headers.get("content-security-policy").is_some(),
        "21c: Content-Security-Policy missing"
    );

    // 21d: Referrer-Policy
    assert!(headers.get("referrer-policy").is_some(), "21d: Referrer-Policy missing");

    // 21e: Cache-Control on token endpoint
    let token_resp = client
        .post(server.api_url("/token"))
        .form(&[("grant_type", "invalid")])
        .send()
        .await
        .unwrap();
    let cc = token_resp
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_lowercase());
    assert!(
        cc.as_ref().map(|v| v.contains("no-store")).unwrap_or(false),
        "21e: Cache-Control: no-store missing on token endpoint"
    );
}

// ── Step 22: response_type Validation ──

#[tokio::test]
async fn response_type_validation() {
    let (server, client) = setup().await;

    // 22a: response_type=token (Implicit Flow)
    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid&state=test123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256",
            CLIENT_ID, REDIRECT_URI
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "22a: response_type=token not rejected");

    // 22b: response_type=id_token
    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=id_token&client_id={}&redirect_uri={}&scope=openid&state=test123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256",
            CLIENT_ID, REDIRECT_URI
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "22b: response_type=id_token not rejected");
}

// ── Step 23: grant_type Validation ──

#[tokio::test]
async fn grant_type_validation() {
    let (server, _client) = setup().await;

    let client = reqwest::Client::builder().user_agent("E2ETest/1.0").build().unwrap();

    // 23a: client_credentials
    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "23a: grant_type=client_credentials accepted");

    // 23b: password (ROPC)
    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "password"),
            ("username", ADMIN_EMAIL),
            ("password", ADMIN_PASSWORD),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "23b: grant_type=password accepted");
}

// ── Step 24: at_hash in ID Token ──

#[tokio::test]
async fn at_hash() {
    let (server, client) = setup().await;

    let tokens = get_fresh_tokens(&server, &client).await;
    let id_token = tokens["id_token"].as_str().unwrap();

    let payload_b64 = id_token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert!(
        payload["at_hash"].as_str().is_some_and(|v| !v.is_empty()),
        "at_hash missing in ID token"
    );
}

// ── Step 24b: Token Substitution Detection ──

#[tokio::test]
async fn token_substitution_detected() {
    use sha2::{Digest, Sha256};

    let (server, client) = setup().await;

    // Get two independent token sets
    let tokens_a = get_fresh_tokens(&server, &client).await;
    let tokens_b = get_fresh_tokens(&server, &client).await;

    let id_token_a = tokens_a["id_token"].as_str().unwrap();
    let access_token_a = tokens_a["access_token"].as_str().unwrap();
    let access_token_b = tokens_b["access_token"].as_str().unwrap();

    // Verify the two access tokens are actually different
    assert_ne!(access_token_a, access_token_b, "need two distinct access tokens");

    // Extract at_hash from id_token_a
    let payload_b64 = id_token_a.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let at_hash = payload["at_hash"].as_str().expect("at_hash missing");

    // Recompute at_hash for the legitimate access token - must match
    let hash_a = Sha256::digest(access_token_a.as_bytes());
    let expected_hash_a = URL_SAFE_NO_PAD.encode(&hash_a[..16]);
    assert_eq!(at_hash, expected_hash_a, "at_hash must match its own access token");

    // Recompute at_hash for the substituted access token - must NOT match
    let hash_b = Sha256::digest(access_token_b.as_bytes());
    let expected_hash_b = URL_SAFE_NO_PAD.encode(&hash_b[..16]);
    assert_ne!(
        at_hash, expected_hash_b,
        "at_hash must NOT match a substituted access token"
    );
}

// ── Step 25: Nonce Mandatory ──

#[tokio::test]
async fn nonce_mandatory() {
    let (server, client) = setup().await;

    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256",
            CLIENT_ID, REDIRECT_URI
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "Authorize without nonce not rejected");
}

// ── Step 26: PKCE code_challenge Length ──

#[tokio::test]
async fn pkce_code_challenge_length() {
    let (server, client) = setup().await;

    // 26a: Too short (10 chars)
    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123&code_challenge=AAAAAAAAAA&code_challenge_method=S256&nonce=testnonce123",
            CLIENT_ID, REDIRECT_URI
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "26a: Short code_challenge not rejected");

    // 26b: Too long (200 chars)
    let long_cc = "A".repeat(200);
    let resp = client
        .get(server.ui_url(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123&code_challenge={}&code_challenge_method=S256&nonce=testnonce123",
            CLIENT_ID, REDIRECT_URI, long_cc
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "26b: Long code_challenge not rejected");
}

// ── Step 27: Token Introspection (RFC 7662) ──

#[tokio::test]
async fn token_introspection() {
    let (server, client) = setup().await;

    let tokens = get_fresh_tokens(&server, &client).await;
    let access_token = tokens["access_token"].as_str().unwrap();

    // 27a: Introspect valid access token
    let resp: serde_json::Value = client
        .post(server.api_url("/introspect"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[("token", access_token), ("token_type_hint", "access_token")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["active"], true, "27a: Valid token not active");

    // 27b: Introspect invalid token
    let resp: serde_json::Value = client
        .post(server.api_url("/introspect"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[("token", "invalid-token-value"), ("token_type_hint", "access_token")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["active"], false, "27b: Invalid token reported as active");

    // 27c: Introspect without client auth
    let resp = client
        .post(server.api_url("/introspect"))
        .form(&[("token", access_token)])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "27c: Introspect without client auth accepted");
}

// ── Step 28: Scope Down/Upscoping ──

#[tokio::test]
async fn scope_downscoping() {
    let (server, client) = setup().await;

    let tokens = get_fresh_tokens(&server, &client).await;
    let refresh_token = tokens["refresh_token"].as_str().unwrap();

    // 28a: Downscoping allowed (openid email profile -> openid)
    let resp: serde_json::Value = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        resp["scope"].as_str().unwrap_or(""),
        "openid",
        "28a: Downscoping failed"
    );

    let new_refresh = resp["refresh_token"].as_str().expect("No new refresh token");

    // 28b: Upscoping forbidden (openid -> openid admin)
    let resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_refresh),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("scope", "openid admin"),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "28b: Scope upscoping accepted");
}

// ── Step 29: Refresh Token Reuse Detection ──

#[tokio::test]
async fn refresh_token_reuse_detection() {
    let (server, client) = setup().await;

    let tokens = get_fresh_tokens(&server, &client).await;
    let rt1 = tokens["refresh_token"].as_str().unwrap().to_string();

    // Refresh: RT1 -> RT2
    let ref1: serde_json::Value = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt1.as_str()),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rt2 = ref1["refresh_token"].as_str().unwrap().to_string();

    // 29a: Reuse RT1 (already consumed) -> must fail
    let reuse_resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt1.as_str()),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(reuse_resp.status(), 200, "29a: Old refresh token reuse accepted");

    // 29b: RT2 should also be revoked (family revocation)
    let rt2_resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt2.as_str()),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(rt2_resp.status(), 200, "29b: Token family not revoked after reuse");
}

// ── Step 30: Auth Code Replay with Cascade Revocation ──

#[tokio::test]
async fn auth_code_replay_cascade() {
    let (server, client) = setup().await;

    let (code, verifier) = get_fresh_code(&server, &client).await;

    // First exchange
    let tokens = exchange_code(&server, &client, &code, &verifier).await;
    let rt = tokens["refresh_token"].as_str().unwrap().to_string();

    // Replay auth code
    let replay = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(replay.status(), 200, "30a: Auth code replay accepted");

    // Refresh token from first exchange should be revoked
    let rt_resp = client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(
        rt_resp.status(),
        200,
        "30b: Refresh token not revoked after code replay"
    );
}

// ── Step 31: RP-Initiated Logout ──

#[tokio::test]
async fn rp_initiated_logout() {
    let (server, client) = setup().await;

    // 31a: Logout with invalid id_token_hint
    let resp = client
        .get(server.ui_url("/logout?id_token_hint=invalid.jwt.token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "31a: Logout with invalid id_token_hint not rejected"
    );

    // 31b: Logout with invalid post_logout_redirect_uri
    let resp = client
        .get(server.ui_url("/logout?post_logout_redirect_uri=https://evil.example.com/steal"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "31b: Logout with invalid post_logout_redirect_uri not rejected"
    );

    // 31c: Logout without params -> redirect to /login
    let resp = client.get(server.ui_url("/logout")).send().await.unwrap();
    let location = resp
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        location.contains("/login"),
        "31c: Logout without params did not redirect to /login (got: {location})"
    );
}

// ── Step 32: Discovery Metadata ──

#[tokio::test]
async fn discovery_metadata() {
    let (server, _client) = setup().await;

    let disc: serde_json::Value = server
        .client
        .get(server.api_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 32a: introspection_endpoint
    assert!(
        disc["introspection_endpoint"].as_str().is_some_and(|v| !v.is_empty()),
        "32a: introspection_endpoint missing in discovery"
    );

    // 32b: end_session_endpoint
    assert!(
        disc["end_session_endpoint"].as_str().is_some_and(|v| !v.is_empty()),
        "32b: end_session_endpoint missing in discovery"
    );
}
