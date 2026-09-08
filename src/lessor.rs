use std::net::Ipv4Addr;

use reqwest::Url;
use serde::Deserialize;
use thiserror::Error;

use crate::model::BmcCandidate;

/// Client for the intentionally narrow, confirmed-BMC portion of lessor's API.
#[derive(Clone)]
pub struct LessorClient {
    base_url: Url,
    client: reqwest::Client,
}

impl LessorClient {
    pub fn new(base_url: Url) -> Result<Self, LessorError> {
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(LessorError::UnsupportedScheme(base_url.scheme().to_owned()));
        }

        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
        })
    }

    pub async fn confirmed_bmcs(
        &self,
        scope_id: Option<u64>,
    ) -> Result<Vec<BmcCandidate>, LessorError> {
        let url = self
            .base_url
            .join("api/v1/devices")
            .map_err(LessorError::InvalidUrl)?;
        let mut request = self.client.get(url).query(&[("kind", "bmc")]);
        if let Some(scope_id) = scope_id {
            request = request.query(&[("scopeId", scope_id)]);
        }

        let response = request.send().await.map_err(LessorError::Request)?;
        let status = response.status();
        if !status.is_success() {
            return Err(LessorError::UnexpectedStatus(status));
        }
        let body: Data<Vec<ScopeDevices>> = response.json().await.map_err(LessorError::Decode)?;

        let mut candidates = Vec::new();
        for scope in body.data {
            for device in scope.devices {
                if device.kind == "bmc" && device.confidence == "confirmed" {
                    candidates.push(BmcCandidate {
                        scope_id: scope.scope.id,
                        scope_name: scope.scope.name.clone(),
                        subnet: scope.scope.subnet,
                        prefix: scope.scope.prefix,
                        ip: device.ip,
                        mac: device.mac,
                        first_seen: device.first_seen,
                        last_seen: device.last_seen,
                    });
                }
            }
        }
        Ok(candidates)
    }
}

#[derive(Debug, Error)]
pub enum LessorError {
    #[error("lessor URL must use http or https, got {0}")]
    UnsupportedScheme(String),
    #[error("invalid lessor API URL")]
    InvalidUrl(#[source] url::ParseError),
    #[error("could not reach lessor")]
    Request(#[source] reqwest::Error),
    #[error("lessor returned HTTP {0}")]
    UnexpectedStatus(reqwest::StatusCode),
    #[error("lessor returned an unexpected response")]
    Decode(#[source] reqwest::Error),
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeDevices {
    scope: ScopeReference,
    devices: Vec<DeviceRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeReference {
    id: u64,
    name: String,
    subnet: Ipv4Addr,
    prefix: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRecord {
    ip: Ipv4Addr,
    mac: Option<String>,
    kind: String,
    confidence: String,
    first_seen: u64,
    last_seen: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    #[test]
    fn accepts_local_http_for_lessors_desktop_api() {
        assert!(LessorClient::new(Url::parse("http://127.0.0.1:6767/").unwrap()).is_ok());
    }

    #[test]
    fn rejects_non_http_lessors() {
        let error = match LessorClient::new(Url::parse("file:///tmp/lessor").unwrap()) {
            Ok(_) => panic!("file URL must not be accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, LessorError::UnsupportedScheme(_)));
    }

    #[tokio::test]
    async fn returns_only_confirmed_bmc_records_from_lessors_aggregate_api() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/devices"))
            .and(query_param("kind", "bmc"))
            .and(query_param("scopeId", "7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "scope": { "id": 7, "name": "Ethernet", "subnet": "192.168.1.0", "prefix": 24 },
                    "devices": [
                        { "ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "kind": "bmc", "confidence": "confirmed", "firstSeen": 1, "lastSeen": 2 },
                        { "ip": "192.168.1.11", "mac": "00:11:22:33:44:56", "kind": "bmc", "confidence": "probable", "firstSeen": 1, "lastSeen": 2 },
                        { "ip": "192.168.1.12", "mac": null, "kind": "device", "confidence": "confirmed", "firstSeen": 1, "lastSeen": 2 }
                    ]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = LessorClient::new(Url::parse(&server.uri()).unwrap()).unwrap();
        let candidates = client.confirmed_bmcs(Some(7)).await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(candidates[0].mac.as_deref(), Some("00:11:22:33:44:55"));
        server.verify().await;
    }
}
