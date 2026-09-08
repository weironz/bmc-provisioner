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
}
