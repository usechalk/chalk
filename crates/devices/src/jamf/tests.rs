//! Jamf connector tests against a realistic mocked Jamf Pro API: the real
//! client-credentials token path, count-based pagination, and honest field
//! mapping.

use super::*;

use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(base: &str) -> JamfConfig {
    JamfConfig {
        enabled: true,
        url: base.to_string(),
        client_id: "api-client".into(),
        client_secret: "api-secret".into(),
    }
}

#[tokio::test]
async fn mobile_devices_page_by_count_and_map_faithfully() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/oauth/token"))
        .and(body_string_contains("client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "tok-jamf", "expires_in": 1200
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v2/mobile-devices"))
        .and(query_param("page", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "totalCount": 2,
            "results": [{
                "id": "jamf-1",
                "serialNumber": "DMPX100",
                "model": "iPad (9th generation)",
                "username": "devon.price@district.test",
                "osVersion": "17.5"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v2/mobile-devices"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "totalCount": 2,
            "results": [{
                "id": "jamf-2",
                "serialNumber": "DMPX200",
                // A bare username is not an email and must not match anyone.
                "username": "cart3-ipad-12"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let devices = JamfConnector::new(config(&server.uri()))
        .fetch_devices()
        .await
        .unwrap();
    assert_eq!(devices.len(), 2);

    assert_eq!(devices[0].external_id, "jamf-1");
    assert_eq!(devices[0].serial_number.as_deref(), Some("DMPX100"));
    assert_eq!(devices[0].make.as_deref(), Some("Apple"));
    assert_eq!(devices[0].asset_type, AssetType::Tablet);
    assert_eq!(
        devices[0].user_email.as_deref(),
        Some("devon.price@district.test")
    );
    assert_eq!(devices[1].user_email, None, "bare usernames never match");
}

/// A total that lies high must not loop forever: an empty page ends the walk.
#[tokio::test]
async fn an_empty_page_ends_the_walk_despite_a_lying_total() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "tok", "expires_in": 1200
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v2/mobile-devices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "totalCount": 999,
            "results": []
        })))
        .mount(&server)
        .await;

    let devices = JamfConnector::new(config(&server.uri()))
        .fetch_devices()
        .await
        .unwrap();
    assert!(devices.is_empty());
}
