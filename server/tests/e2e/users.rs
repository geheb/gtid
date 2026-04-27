use super::*;

#[tokio::test]
async fn create_user_success() {
    let server = TestServer::start().await;
    let client = server.new_client();
    setup_test_client(&server, &client).await;

    let resp = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header("Accept-Language", "en")
        .json(&serde_json::json!({
            "email": "newuser@example.com",
            "password": "Str0ng!!Pass99",
            "display_name": "New User",
            "roles": ["admin"],
            "is_confirmed": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn create_user_unconfirmed_triggers_email() {
    let server = TestServer::start().await;
    let client = server.new_client();
    setup_test_client(&server, &client).await;

    let resp = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header("Accept-Language", "de")
        .json(&serde_json::json!({
            "email": "unconfirmed@example.com",
            "password": "Str0ng!!Pass99",
            "roles": ["admin"],
            "is_confirmed": false
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn create_user_unauthorized() {
    let server = TestServer::start().await;
    let client = server.new_client();

    let resp = client
        .post(server.api_url("/admin/users"))
        .json(&serde_json::json!({
            "email": "newuser@example.com",
            "password": "Str0ng!!Pass99",
            "roles": ["admin"],
            "is_confirmed": true
        }))
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), 204);
}

#[tokio::test]
async fn create_user_invalid_role() {
    let server = TestServer::start().await;
    let client = server.new_client();
    setup_test_client(&server, &client).await;

    let resp = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .json(&serde_json::json!({
            "email": "newuser@example.com",
            "password": "Str0ng!!Pass99",
            "roles": ["superuser"],
            "is_confirmed": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn create_user_duplicate_email() {
    let server = TestServer::start().await;
    let client = server.new_client();
    setup_test_client(&server, &client).await;

    let body = serde_json::json!({
        "email": "duplicate@example.com",
        "password": "Str0ng!!Pass99",
        "roles": ["admin"],
        "is_confirmed": true
    });

    let resp1 = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 204);

    let resp2 = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 400);
}

#[tokio::test]
async fn create_user_weak_password() {
    let server = TestServer::start().await;
    let client = server.new_client();
    setup_test_client(&server, &client).await;

    let resp = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .json(&serde_json::json!({
            "email": "weak@example.com",
            "password": "weak",
            "roles": ["admin"],
            "is_confirmed": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn create_user_empty_roles() {
    let server = TestServer::start().await;
    let client = server.new_client();
    setup_test_client(&server, &client).await;

    let resp = client
        .post(server.api_url("/admin/users"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .json(&serde_json::json!({
            "email": "noroles@example.com",
            "password": "Str0ng!!Pass99",
            "roles": [],
            "is_confirmed": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}
