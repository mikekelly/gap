//! Integration tests for the Management API

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

// Helper to create test app
async fn create_test_app() -> (
    axum::Router,
    acp_server::api::ApiState,
) {
    let state = acp_server::api::ApiState::new(9443, 9080);

    // Set a test password hash (password: "testpass123")
    let salt = SaltString::from_b64("dGVzdHNhbHQxMjM").unwrap();
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(b"testpass123", &salt)
        .unwrap()
        .to_string();
    state.set_password_hash(hash).await;

    let app = acp_server::api::create_router(state.clone());
    (app, state)
}

// Helper to compute SHA512 hash of password (client-side hashing)
fn sha512_hash(password: &str) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[tokio::test]
async fn test_status_endpoint_no_auth() {
    let (app, _state) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(status.get("version").is_some());
    assert!(status.get("uptime_seconds").is_some());
    assert_eq!(status["proxy_port"], 9443);
    assert_eq!(status["api_port"], 9080);
}

#[tokio::test]
async fn test_plugins_list_requires_auth() {
    let (app, _state) = create_test_app().await;

    // Without auth should fail
    let response = app
        .oneshot(
            Request::builder()
                .uri("/plugins")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_plugins_list_with_valid_auth() {
    let (app, _state) = create_test_app().await;

    // With valid password_hash in body
    let password_hash = sha512_hash("testpass123");
    let body_json = json!({
        "password_hash": password_hash
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/plugins")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed (200 OK)
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_plugins_list_with_invalid_auth() {
    let (app, _state) = create_test_app().await;

    // With wrong password
    let wrong_hash = sha512_hash("wrongpassword");
    let body_json = json!({
        "password_hash": wrong_hash
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/plugins")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail with 401
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_credentials_set() {
    let (app, _state) = create_test_app().await;

    let password_hash = sha512_hash("testpass123");
    let body_json = json!({
        "password_hash": password_hash,
        "value": "my-secret-key"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credentials/exa/api_key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_tokens_list() {
    let (app, _state) = create_test_app().await;

    let password_hash = sha512_hash("testpass123");
    let body_json = json!({
        "password_hash": password_hash
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/tokens")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_tokens_create() {
    let (app, _state) = create_test_app().await;

    let password_hash = sha512_hash("testpass123");
    let body_json = json!({
        "password_hash": password_hash,
        "name": "Test Agent"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tokens")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Response should contain the token
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(token_response.get("id").is_some());
    assert!(token_response.get("token").is_some()); // Full token returned on creation
    assert_eq!(token_response["name"], "Test Agent");
}

#[tokio::test]
async fn test_activity_list() {
    let (app, _state) = create_test_app().await;

    let password_hash = sha512_hash("testpass123");
    let body_json = json!({
        "password_hash": password_hash
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/activity")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
