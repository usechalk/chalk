//! Intune connector tests against a mocked Graph API: token flow, pagination
//! via @odata.nextLink, and honest field mapping.

use super::*;

use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(base: &str) -> IntuneConfig {
    IntuneConfig {
        enabled: true,
        tenant_id: "contoso.k12.test".into(),
        client_id: "app-id".into(),
        client_secret: "app-secret".into(),
        base_url: Some(base.to_string()),
    }
}

#[tokio::test]
async fn devices_page_through_and_map_faithfully() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contoso.k12.test/oauth2/v2.0/token"))
        .and(body_string_contains("client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "tok-123", "expires_in": 3599
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Page 1 links to page 2; page 2 ends the walk.
    Mock::given(method("GET"))
        .and(path("/v1.0/deviceManagement/managedDevices"))
        .and(query_param("$top", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "int-1",
                "serialNumber": "SER-100",
                "manufacturer": "Dell",
                "model": "Latitude 3310",
                "osVersion": "10.0.26100",
                "operatingSystem": "Windows",
                "userPrincipalName": "maya.chen@district.test"
            }],
            "@odata.nextLink": format!("{}/v1.0/deviceManagement/managedDevices?page=2", server.uri())
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/deviceManagement/managedDevices"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "int-2",
                "serialNumber": "SER-200",
                "operatingSystem": "iPadOS",
                // Not an email: must not be offered for matching.
                "userPrincipalName": "kiosk-cart-3"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let devices = IntuneConnector::new(config(&server.uri()))
        .fetch_devices()
        .await
        .unwrap();
    assert_eq!(devices.len(), 2, "both pages walked");

    assert_eq!(devices[0].external_id, "int-1");
    assert_eq!(devices[0].serial_number.as_deref(), Some("SER-100"));
    assert_eq!(devices[0].make.as_deref(), Some("Dell"));
    assert_eq!(devices[0].asset_type, AssetType::Laptop, "Windows → laptop");
    assert_eq!(
        devices[0].user_email.as_deref(),
        Some("maya.chen@district.test")
    );

    assert_eq!(devices[1].asset_type, AssetType::Tablet, "iPadOS → tablet");
    assert_eq!(
        devices[1].user_email, None,
        "a UPN that is not an email is not offered for matching"
    );
}

#[tokio::test]
async fn a_refused_token_is_an_error_that_does_not_echo_the_secret() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contoso.k12.test/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let err = IntuneConnector::new(config(&server.uri()))
        .fetch_devices()
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("refused"), "got {text}");
    assert!(
        !text.contains("app-secret"),
        "the client secret must never appear in an error"
    );
}
