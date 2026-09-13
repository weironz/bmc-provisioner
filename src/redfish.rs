use std::{net::Ipv4Addr, sync::Arc};

use reqwest::{
    Response, StatusCode, Url,
    header::{COOKIE, ETAG, HeaderValue, IF_MATCH, SET_COOKIE},
};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::TlsConnector;

use crate::model::{Credentials, StaticNetwork};

/// Standard Redfish resources discovered dynamically from the Service Root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedfishInventory {
    pub account: AccountResource,
    pub ethernet_interfaces: Vec<EthernetInterface>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountResource {
    pub uri: String,
    pub password_change_required: bool,
    pub change_password_action: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthernetInterface {
    pub uri: String,
    pub id: String,
    pub name: Option<String>,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub link_status: Option<String>,
}

/// SHA-256 fingerprint of the leaf certificate currently served by a BMC.
/// It is public identity data, unlike an account credential, and is safe to return to the UI.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateFingerprint {
    pub sha256: String,
}

impl CertificateFingerprint {
    pub fn parse(value: &str) -> Result<Self, RedfishError> {
        let normalized: String = value
            .chars()
            .filter(|character| !matches!(character, ':' | ' ' | '\t'))
            .collect::<String>()
            .to_ascii_lowercase();
        if normalized.len() != 64
            || !normalized
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(RedfishError::InvalidCertificateFingerprint);
        }
        Ok(Self { sha256: normalized })
    }

    fn from_der(certificate: &[u8]) -> Self {
        let hash = Sha256::digest(certificate);
        let sha256 = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        Self { sha256 }
    }
}

/// Reads the current leaf certificate without sending credentials. Its TLS handshake still checks
/// proof of private-key possession; only chain and hostname validation are deferred to explicit
/// user fingerprint confirmation.
pub async fn probe_certificate(ip: Ipv4Addr) -> Result<CertificateFingerprint, RedfishError> {
    let stream = tokio::net::TcpStream::connect((ip, 443))
        .await
        .map_err(RedfishError::CertificateProbe)?;
    let configuration = pinned_tls_config(None);
    let connector = TlsConnector::from(Arc::new(configuration));
    let connection = connector
        .connect(ServerName::from(ip), stream)
        .await
        .map_err(RedfishError::CertificateProbe)?;
    let certificate = connection
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or(RedfishError::CertificateMissing)?;
    Ok(CertificateFingerprint::from_der(certificate.as_ref()))
}

/// Redfish client using HTTP Basic authentication. Certificate validation remains enabled.
#[derive(Clone)]
pub struct RedfishClient {
    base_url: Url,
    client: reqwest::Client,
    username: String,
    password: String,
}

impl RedfishClient {
    pub fn for_ipv4(ip: Ipv4Addr, credentials: &Credentials) -> Result<Self, RedfishError> {
        Self::for_ipv4_with_fingerprint(ip, credentials, None)
    }

    /// Uses platform trust by default. When the user has explicitly confirmed a BMC's leaf
    /// fingerprint, the connection instead pins that exact certificate for every request.
    pub fn for_ipv4_with_fingerprint(
        ip: Ipv4Addr,
        credentials: &Credentials,
        fingerprint: Option<&str>,
    ) -> Result<Self, RedfishError> {
        let base_url = Url::parse(&format!("https://{ip}/")).map_err(RedfishError::InvalidUrl)?;
        // BMC addresses are always contacted directly.  In a corporate environment reqwest
        // inherits HTTP(S)_PROXY by default; sending RFC1918 Redfish traffic to that proxy makes
        // a reachable BMC look like a TLS or authentication failure.
        let client = https_client(fingerprint)?;
        Self::from_client(base_url, credentials, client)
    }

    pub fn new(base_url: Url, credentials: &Credentials) -> Result<Self, RedfishError> {
        if base_url.scheme() != "https" {
            return Err(RedfishError::HttpsRequired);
        }
        if base_url.host_str().is_none() {
            return Err(RedfishError::MissingHost);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .map_err(RedfishError::Client)?;
        Self::from_client(base_url, credentials, client)
    }

    #[cfg(test)]
    fn new_for_mock(base_url: Url, credentials: &Credentials) -> Self {
        assert_eq!(
            base_url.scheme(),
            "http",
            "mock Redfish must use local HTTP"
        );
        Self {
            base_url,
            client: reqwest::Client::new(),
            username: credentials.username.clone(),
            password: credentials.current_password.clone(),
        }
    }

    fn from_client(
        base_url: Url,
        credentials: &Credentials,
        client: reqwest::Client,
    ) -> Result<Self, RedfishError> {
        if base_url.scheme() != "https" {
            return Err(RedfishError::HttpsRequired);
        }
        if base_url.host_str().is_none() {
            return Err(RedfishError::MissingHost);
        }
        Ok(Self {
            base_url,
            client,
            username: credentials.username.clone(),
            password: credentials.current_password.clone(),
        })
    }

    /// Recreate authentication after an account password has changed.
    pub fn with_password(&self, password: String) -> Self {
        Self {
            base_url: self.base_url.clone(),
            client: self.client.clone(),
            username: self.username.clone(),
            password,
        }
    }

    /// Move an already authenticated client to the BMC's configured IPv4 address.
    /// The caller uses this only after changing the BMC network configuration.
    pub fn at_ipv4(&self, ip: Ipv4Addr) -> Result<Self, RedfishError> {
        let base_url = Url::parse(&format!("https://{ip}/")).map_err(RedfishError::InvalidUrl)?;
        Ok(Self {
            base_url,
            client: self.client.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        })
    }

    pub async fn discover(&self) -> Result<RedfishInventory, RedfishError> {
        let root: ServiceRoot = self.get_json("/redfish/v1/").await?;
        let account_service: AccountService = self.get_json(&root.account_service.odata_id).await?;
        let account_collection: Collection =
            self.get_json(&account_service.accounts.odata_id).await?;

        let mut matched_account = None;
        for member in account_collection.members {
            let account: ManagerAccount = self.get_json(&member.odata_id).await?;
            if account.user_name.as_deref() == Some(self.username.as_str()) {
                matched_account = Some(AccountResource {
                    uri: member.odata_id,
                    password_change_required: account.password_change_required.unwrap_or(false),
                    change_password_action: account.change_password_action(),
                });
                break;
            }
        }
        let account =
            matched_account.ok_or_else(|| RedfishError::AccountNotFound(self.username.clone()))?;

        let managers: Collection = self.get_json(&root.managers.odata_id).await?;
        let manager = managers
            .members
            .into_iter()
            .next()
            .ok_or(RedfishError::NoManager)?;
        let manager: Manager = self.get_json(&manager.odata_id).await?;
        let interface_collection = manager
            .ethernet_interfaces
            .ok_or(RedfishError::NoEthernetInterfaces)?;
        let interfaces: Collection = self.get_json(&interface_collection.odata_id).await?;
        let mut ethernet_interfaces = Vec::with_capacity(interfaces.members.len());
        for member in interfaces.members {
            let interface: EthernetInterfaceResponse = self.get_json(&member.odata_id).await?;
            ethernet_interfaces.push(EthernetInterface {
                uri: member.odata_id,
                id: interface.id.unwrap_or_default(),
                name: interface.name,
                mac_address: interface.mac_address,
                ipv4_addresses: interface
                    .ipv4_addresses
                    .into_iter()
                    .filter_map(|address| address.address)
                    .collect(),
                link_status: interface.link_status,
            });
        }
        if ethernet_interfaces.is_empty() {
            return Err(RedfishError::NoEthernetInterfaces);
        }

        Ok(RedfishInventory {
            account,
            ethernet_interfaces,
        })
    }

    pub async fn change_password(
        &self,
        account: &AccountResource,
        new_password: &str,
    ) -> Result<(), RedfishError> {
        if account.password_change_required
            && let Some(action) = &account.change_password_action
        {
            self.send_json(
                reqwest::Method::POST,
                action,
                json!({
                    "Password": new_password,
                    "SessionAccountPassword": self.password,
                }),
            )
            .await?;
            return Ok(());
        }

        self.send_json(
            reqwest::Method::PATCH,
            &account.uri,
            json!({ "Password": new_password }),
        )
        .await
    }

    pub async fn configure_static_ipv4(
        &self,
        interface_uri: &str,
        network: &StaticNetwork,
    ) -> Result<(), RedfishError> {
        network.validate().map_err(RedfishError::InvalidNetwork)?;
        // Some compliant Redfish implementations (including AMI) reject PATCH without the
        // ETag obtained from a preceding GET. Reading immediately before writing also protects
        // us from overwriting a simultaneous operator change.
        let etag = self.resource_etag(interface_uri).await?;
        let combined_result = self.send_json_with_if_match(
            reqwest::Method::PATCH,
            interface_uri,
            static_ipv4_payload(network),
            etag.clone(),
        );

        match combined_result.await {
            Ok(()) => Ok(()),
            // AMI SyncAgent firmware rejects a combined DHCP-disable and static-address PATCH
            // with this specific message. Do not use this fallback for generic 400 responses:
            // those can indicate an invalid address or a non-writable interface.
            Err(error) if requires_separate_dhcpv4_disable(&error) => {
                self.send_json_with_if_match(
                    reqwest::Method::PATCH,
                    interface_uri,
                    dhcpv4_disable_payload(),
                    etag,
                )
                .await?;

                // A successful PATCH may replace the entity tag. Fetch it again before the
                // second write so the two-step path retains the same concurrency guarantee.
                let refreshed_etag = self.resource_etag(interface_uri).await.map_err(|error| {
                    RedfishError::DhcpV4DisabledButStaticIpv4Incomplete(Box::new(error))
                })?;
                self.send_json_with_if_match(
                    reqwest::Method::PATCH,
                    interface_uri,
                    static_addresses_payload(network),
                    refreshed_etag,
                )
                .await
                .map_err(|error| {
                    RedfishError::DhcpV4DisabledButStaticIpv4Incomplete(Box::new(error))
                })
            }
            // Some AMI firmware rejects the inverse combined transition with
            // Ami.1.0.DifferentIpSeries even when the requested address and gateway share the
            // supplied subnet. Its own registry only provides a generic message, so use this
            // ordering only for the precise vendor MessageId: install the static address first,
            // then disable DHCP using a refreshed ETag.
            Err(error) if requires_static_before_dhcpv4_disable(&error) => {
                self.send_json_with_if_match(
                    reqwest::Method::PATCH,
                    interface_uri,
                    static_addresses_payload(network),
                    etag,
                )
                .await?;

                let refreshed_etag = self.resource_etag(interface_uri).await.map_err(|error| {
                    RedfishError::StaticIpv4ConfiguredButDhcpV4StillEnabled(Box::new(error))
                })?;
                self.send_json_with_if_match(
                    reqwest::Method::PATCH,
                    interface_uri,
                    dhcpv4_disable_payload(),
                    refreshed_etag,
                )
                .await
                .map_err(|error| {
                    RedfishError::StaticIpv4ConfiguredButDhcpV4StillEnabled(Box::new(error))
                })
            }
            Err(error) => Err(error),
        }
    }

    /// A short authenticated request used after the network address has changed.
    pub async fn verify_connection(&self) -> Result<(), RedfishError> {
        let _: ServiceRoot = self.get_json("/redfish/v1/").await?;
        Ok(())
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        resource: &str,
    ) -> Result<T, RedfishError> {
        let url = self.resource_url(resource)?;
        let response = self
            .client
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(RedfishError::Request)?;
        let response = ensure_success(response).await?;
        response.json().await.map_err(RedfishError::Decode)
    }

    async fn send_json(
        &self,
        method: reqwest::Method,
        resource: &str,
        body: Value,
    ) -> Result<(), RedfishError> {
        self.send_json_with_if_match(method, resource, body, None)
            .await
    }

    async fn send_json_with_if_match(
        &self,
        method: reqwest::Method,
        resource: &str,
        body: Value,
        etag: Option<HeaderValue>,
    ) -> Result<(), RedfishError> {
        let url = self.resource_url(resource)?;
        let mut request = self
            .client
            .request(method, url)
            .basic_auth(&self.username, Some(&self.password))
            .json(&body);
        if let Some(etag) = etag {
            request = request.header(IF_MATCH, etag);
        }
        let response = request.send().await.map_err(RedfishError::Request)?;
        ensure_success(response).await.map(|_| ())
    }

    /// Get a resource's opaque entity tag. The ETag response header is canonical; the
    /// `@odata.etag` property is a standards-defined fallback for firmware that omits it.
    async fn resource_etag(&self, resource: &str) -> Result<Option<HeaderValue>, RedfishError> {
        let url = self.resource_url(resource)?;
        let response = self
            .client
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(RedfishError::Request)?;
        let response = ensure_success(response).await?;
        if let Some(etag) = response.headers().get(ETAG) {
            return Ok(Some(etag.clone()));
        }
        let body: Value = response.json().await.map_err(RedfishError::Decode)?;
        Ok(body
            .get("@odata.etag")
            .and_then(Value::as_str)
            .and_then(|etag| HeaderValue::from_str(etag).ok()))
    }

    /// Restricts BMC-supplied `@odata.id` links to this BMC's HTTPS origin.
    fn resource_url(&self, resource: &str) -> Result<Url, RedfishError> {
        let url = self
            .base_url
            .join(resource)
            .map_err(RedfishError::InvalidUrl)?;
        if url.scheme() != self.base_url.scheme()
            || url.host_str() != self.base_url.host_str()
            || url.port_or_known_default() != self.base_url.port_or_known_default()
        {
            return Err(RedfishError::CrossOriginLink);
        }
        Ok(url)
    }
}

/// Detect the narrowly scoped AMI first-login API before considering its use.  This does not
/// authenticate and does not modify the BMC.  A normal Redfish implementation never needs it.
pub async fn ami_web_first_login_supported(
    ip: Ipv4Addr,
    fingerprint: Option<&str>,
) -> Result<bool, RedfishError> {
    let client = AmiWebFirstLoginClient::for_ipv4(ip, fingerprint)?;
    client.supported().await
}

/// Change an AMI BMC's factory password only after the public UI signature has been verified.
/// The firmware blocks the standard Redfish ManagerAccount resource in this state, so this is a
/// deliberately small bridge back to the normal Redfish workflow rather than a general web API.
pub async fn reset_ami_web_initial_password(
    ip: Ipv4Addr,
    credentials: &Credentials,
    fingerprint: Option<&str>,
) -> Result<(), RedfishError> {
    let client = AmiWebFirstLoginClient::for_ipv4(ip, fingerprint)?;
    client.reset_password(credentials).await
}

fn https_client(fingerprint: Option<&str>) -> Result<reqwest::Client, RedfishError> {
    match fingerprint {
        Some(fingerprint) => {
            let fingerprint = CertificateFingerprint::parse(fingerprint)?;
            reqwest::Client::builder()
                .no_proxy()
                .use_preconfigured_tls(pinned_tls_config(Some(fingerprint)))
                .build()
                .map_err(RedfishError::Client)
        }
        None => reqwest::Client::builder()
            .no_proxy()
            .build()
            .map_err(RedfishError::Client),
    }
}

struct AmiWebFirstLoginClient {
    base_url: Url,
    client: reqwest::Client,
}

impl AmiWebFirstLoginClient {
    fn for_ipv4(ip: Ipv4Addr, fingerprint: Option<&str>) -> Result<Self, RedfishError> {
        let base_url = Url::parse(&format!("https://{ip}/")).map_err(RedfishError::InvalidUrl)?;
        Ok(Self {
            base_url,
            client: https_client(fingerprint)?,
        })
    }

    #[cfg(test)]
    fn new_for_mock(base_url: Url) -> Self {
        assert_eq!(
            base_url.scheme(),
            "http",
            "mock AMI API must use local HTTP"
        );
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    async fn supported(&self) -> Result<bool, RedfishError> {
        let response = self
            .client
            .get(self.url("/source.min.js")?)
            .send()
            .await
            .map_err(RedfishError::Request)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let response = ensure_success(response).await?;
        let script = response.text().await.map_err(RedfishError::Decode)?;
        Ok(script.contains("/api/session") && script.contains("/api/updatenew_password"))
    }

    async fn reset_password(&self, credentials: &Credentials) -> Result<(), RedfishError> {
        if !self.supported().await? {
            return Err(RedfishError::AmiWebBootstrapUnsupported);
        }
        let response = self
            .client
            .post(self.url("/api/session")?)
            .form(&[
                ("username", credentials.username.as_str()),
                ("password", credentials.current_password.as_str()),
            ])
            .send()
            .await
            .map_err(RedfishError::Request)?;
        let response = ensure_success(response).await?;
        let cookie = response_cookie(&response).ok_or(RedfishError::AmiWebBootstrapRejected)?;
        let login: Value = response.json().await.map_err(RedfishError::Decode)?;
        let csrf = login
            .get("CSRFToken")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or(RedfishError::AmiWebBootstrapRejected)?;
        if login.get("passwordStatus").and_then(Value::as_i64) != Some(1) {
            return Err(RedfishError::AmiWebBootstrapRejected);
        }

        let result = self
            .client
            .post(self.url("/api/updatenew_password")?)
            .header(COOKIE, &cookie)
            .header("X-CSRFTOKEN", csrf)
            .form(&[
                ("password", credentials.new_password.as_str()),
                ("username", credentials.username.as_str()),
            ])
            .send()
            .await
            .map_err(RedfishError::Request)?;
        let result = ensure_success(result).await?;
        let result: Value = result.json().await.map_err(RedfishError::Decode)?;
        let accepted = result
            .get("code")
            .and_then(Value::as_i64)
            .is_some_and(|code| (code as u64 & 0xff) == 0);
        if !accepted {
            return Err(RedfishError::AmiWebBootstrapRejected);
        }

        // Do not retain the privileged browser-like session.  Logout is best effort because the
        // password change may invalidate it immediately; its failure cannot undo the change.
        let _ = self
            .client
            .delete(self.url("/api/session")?)
            .header(COOKIE, &cookie)
            .header("X-CSRFTOKEN", csrf)
            .send()
            .await;
        Ok(())
    }

    fn url(&self, path: &str) -> Result<Url, RedfishError> {
        self.base_url.join(path).map_err(RedfishError::InvalidUrl)
    }
}

fn response_cookie(response: &Response) -> Option<String> {
    let cookies: Vec<_> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter(|value| value.contains('='))
        .collect();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    expected: Option<CertificateFingerprint>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if let Some(expected) = &self.expected
            && CertificateFingerprint::from_der(end_entity.as_ref()) != *expected
        {
            return Err(RustlsError::General(
                "BMC certificate did not match the approved fingerprint".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn pinned_tls_config(fingerprint: Option<CertificateFingerprint>) -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificateVerifier {
            expected: fingerprint,
        }))
        .with_no_client_auth()
}

fn static_ipv4_payload(network: &StaticNetwork) -> Value {
    json!({
        "DHCPv4": { "DHCPEnabled": false },
        "IPv4StaticAddresses": static_addresses(network),
    })
}

fn dhcpv4_disable_payload() -> Value {
    json!({ "DHCPv4": { "DHCPEnabled": false } })
}

fn static_addresses_payload(network: &StaticNetwork) -> Value {
    json!({
        "IPv4StaticAddresses": static_addresses(network),
    })
}

fn static_addresses(network: &StaticNetwork) -> Value {
    json!([{
            "Address": network.address.to_string(),
            "SubnetMask": network.subnet_mask_string(),
            "Gateway": network.gateway.to_string(),
    }])
}

fn requires_separate_dhcpv4_disable(error: &RedfishError) -> bool {
    matches!(
        error,
        RedfishError::UnexpectedStatus {
            status: StatusCode::BAD_REQUEST,
            message_id: Some(message_id),
        } if message_id == "SyncAgent.1.0.DisableDHCPv4"
    )
}

fn requires_static_before_dhcpv4_disable(error: &RedfishError) -> bool {
    matches!(
        error,
        RedfishError::UnexpectedStatus {
            status: StatusCode::BAD_REQUEST,
            message_id: Some(message_id),
        } if message_id == "Ami.1.0.DifferentIpSeries"
    )
}

async fn ensure_success(response: Response) -> Result<Response, RedfishError> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        Err(RedfishError::AuthenticationFailed)
    } else {
        // Redfish standard errors contain stable MessageId values such as
        // `Base.1.17.PropertyNotWritable`. Keep only that identifier: it is useful for
        // selecting a firmware-compatible write path, without retaining an arbitrary BMC
        // response body (which may contain implementation-specific details).
        let message_id = response
            .json::<Value>()
            .await
            .ok()
            .and_then(|body| redfish_message_id(&body));
        Err(RedfishError::UnexpectedStatus { status, message_id })
    }
}

fn redfish_message_id(body: &Value) -> Option<String> {
    let error = body.get("error")?;
    let candidates = error
        .get("@Message.ExtendedInfo")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| entry.get("MessageId"))
        .chain(std::iter::once(error.get("code")));
    candidates
        .flatten()
        .filter_map(Value::as_str)
        .find(|value| {
            !value.is_empty()
                && value.len() <= 160
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
                })
        })
        .map(ToOwned::to_owned)
}

#[derive(Debug, Error)]
pub enum RedfishError {
    #[error("invalid Redfish URL")]
    InvalidUrl(#[source] url::ParseError),
    #[error("Redfish connections must use HTTPS")]
    HttpsRequired,
    #[error("Redfish URL is missing a host")]
    MissingHost,
    #[error("BMC certificate fingerprint must be a SHA-256 value")]
    InvalidCertificateFingerprint,
    #[error("could not inspect the BMC TLS certificate")]
    CertificateProbe(#[source] std::io::Error),
    #[error("BMC did not present a TLS certificate")]
    CertificateMissing,
    #[error("could not create the HTTPS client")]
    Client(#[source] reqwest::Error),
    #[error("Redfish returned a link outside the selected BMC")]
    CrossOriginLink,
    #[error("could not reach the BMC Redfish service")]
    Request(#[source] reqwest::Error),
    #[error("BMC authentication failed")]
    AuthenticationFailed,
    #[error("this BMC does not expose the supported AMI first-login password API")]
    AmiWebBootstrapUnsupported,
    #[error("BMC rejected the AMI first-login password change")]
    AmiWebBootstrapRejected,
    #[error(
        "Redfish returned HTTP {status}{message_id}",
        message_id = message_id
            .as_deref()
            .map(|value| format!(" ({value})"))
            .unwrap_or_default()
    )]
    UnexpectedStatus {
        status: StatusCode,
        message_id: Option<String>,
    },
    #[error("BMC accepted DHCPv4 disable, but static IPv4 configuration did not complete")]
    DhcpV4DisabledButStaticIpv4Incomplete(#[source] Box<RedfishError>),
    #[error("BMC accepted static IPv4, but DHCPv4 disable did not complete")]
    StaticIpv4ConfiguredButDhcpV4StillEnabled(#[source] Box<RedfishError>),
    #[error("Redfish returned an unexpected response")]
    Decode(#[source] reqwest::Error),
    #[error("the Redfish account for {0:?} was not found")]
    AccountNotFound(String),
    #[error("Redfish did not expose a Manager resource")]
    NoManager,
    #[error("Redfish did not expose a Manager EthernetInterface resource")]
    NoEthernetInterfaces,
    #[error(transparent)]
    InvalidNetwork(#[from] crate::model::NetworkValidationError),
}

#[derive(Deserialize)]
struct Link {
    #[serde(rename = "@odata.id")]
    odata_id: String,
}

#[derive(Deserialize)]
struct ServiceRoot {
    #[serde(rename = "AccountService")]
    account_service: Link,
    #[serde(rename = "Managers")]
    managers: Link,
}

#[derive(Deserialize)]
struct AccountService {
    #[serde(rename = "Accounts")]
    accounts: Link,
}

#[derive(Deserialize)]
struct Collection {
    #[serde(rename = "Members")]
    members: Vec<Link>,
}

#[derive(Deserialize)]
struct Manager {
    #[serde(rename = "EthernetInterfaces")]
    ethernet_interfaces: Option<Link>,
}

#[derive(Deserialize)]
struct ManagerAccount {
    #[serde(rename = "UserName")]
    user_name: Option<String>,
    #[serde(rename = "PasswordChangeRequired")]
    password_change_required: Option<bool>,
    #[serde(rename = "Actions", default)]
    actions: Value,
}

impl ManagerAccount {
    fn change_password_action(&self) -> Option<String> {
        self.actions
            .get("#ManagerAccount.ChangePassword")?
            .get("target")?
            .as_str()
            .map(ToOwned::to_owned)
    }
}

#[derive(Deserialize)]
struct EthernetInterfaceResponse {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
    #[serde(rename = "IPv4Addresses", default)]
    ipv4_addresses: Vec<Ipv4Address>,
    #[serde(rename = "LinkStatus")]
    link_status: Option<String>,
}

#[derive(Deserialize)]
struct Ipv4Address {
    #[serde(rename = "Address")]
    address: Option<Ipv4Addr>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    fn credentials() -> Credentials {
        Credentials {
            username: "admin".to_owned(),
            current_password: "not-in-output".to_owned(),
            new_password: "another-secret".to_owned(),
        }
    }

    #[test]
    fn keeps_odata_links_on_the_selected_bmc() {
        let client =
            RedfishClient::new(Url::parse("https://192.168.1.2/").unwrap(), &credentials())
                .unwrap();
        assert_eq!(
            client
                .resource_url("/redfish/v1/Managers/BMC")
                .unwrap()
                .as_str(),
            "https://192.168.1.2/redfish/v1/Managers/BMC"
        );
        assert!(matches!(
            client.resource_url("https://example.invalid/redfish/v1/"),
            Err(RedfishError::CrossOriginLink)
        ));
    }

    #[test]
    fn refuses_plain_http_for_bmc_credentials() {
        let error =
            match RedfishClient::new(Url::parse("http://192.168.1.2/").unwrap(), &credentials()) {
                Ok(_) => panic!("plain HTTP must not be accepted"),
                Err(error) => error,
            };
        assert!(matches!(error, RedfishError::HttpsRequired));
    }

    async fn mock_discovery(server: &MockServer, password_change_required: bool, action: bool) {
        let root = json!({
            "AccountService": { "@odata.id": "/redfish/v1/AccountService" },
            "Managers": { "@odata.id": "/redfish/v1/Managers" }
        });
        let account_service =
            json!({ "Accounts": { "@odata.id": "/redfish/v1/AccountService/Accounts" } });
        let accounts =
            json!({ "Members": [{ "@odata.id": "/redfish/v1/AccountService/Accounts/admin" }] });
        let actions = if action {
            json!({ "#ManagerAccount.ChangePassword": { "target": "/redfish/v1/AccountService/Accounts/admin/Actions/ManagerAccount.ChangePassword" } })
        } else {
            json!({})
        };
        let account = json!({
            "UserName": "admin",
            "PasswordChangeRequired": password_change_required,
            "Actions": actions
        });
        let managers = json!({ "Members": [{ "@odata.id": "/redfish/v1/Managers/BMC" }] });
        let manager = json!({ "EthernetInterfaces": { "@odata.id": "/redfish/v1/Managers/BMC/EthernetInterfaces" } });
        let interfaces = json!({ "Members": [{ "@odata.id": "/redfish/v1/Managers/BMC/EthernetInterfaces/eth0" }] });
        let interface = json!({
            "Id": "eth0", "Name": "BMC management", "MACAddress": "00:11:22:33:44:55",
            "IPv4Addresses": [{ "Address": "192.168.1.10" }], "LinkStatus": "LinkUp"
        });

        for (resource, body) in [
            ("/redfish/v1/", root),
            ("/redfish/v1/AccountService", account_service),
            ("/redfish/v1/AccountService/Accounts", accounts),
            ("/redfish/v1/AccountService/Accounts/admin", account),
            ("/redfish/v1/Managers", managers),
            ("/redfish/v1/Managers/BMC", manager),
            ("/redfish/v1/Managers/BMC/EthernetInterfaces", interfaces),
            (
                "/redfish/v1/Managers/BMC/EthernetInterfaces/eth0",
                interface,
            ),
        ] {
            let response = if resource == "/redfish/v1/Managers/BMC/EthernetInterfaces/eth0" {
                ResponseTemplate::new(200)
                    .set_body_json(body)
                    .insert_header("etag", "\"resource-version-1\"")
            } else {
                ResponseTemplate::new(200).set_body_json(body)
            };
            Mock::given(method("GET"))
                .and(path(resource))
                .respond_with(response)
                .mount(server)
                .await;
        }
    }

    #[tokio::test]
    async fn discovers_resources_and_uses_patch_for_normal_password_change() {
        let server = MockServer::start().await;
        mock_discovery(&server, false, false).await;
        Mock::given(method("PATCH"))
            .and(path("/redfish/v1/AccountService/Accounts/admin"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/redfish/v1/Managers/BMC/EthernetInterfaces/eth0"))
            .and(header("if-match", "\"resource-version-1\""))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let inventory = client.discover().await.unwrap();
        assert_eq!(
            inventory.account.uri,
            "/redfish/v1/AccountService/Accounts/admin"
        );
        assert_eq!(inventory.ethernet_interfaces[0].id, "eth0");
        client
            .change_password(&inventory.account, "new-password")
            .await
            .unwrap();
        client
            .configure_static_ipv4(
                &inventory.ethernet_interfaces[0].uri,
                &StaticNetwork {
                    address: Ipv4Addr::new(10, 10, 1, 9),
                    prefix: 24,
                    gateway: Ipv4Addr::new(10, 10, 1, 1),
                },
            )
            .await
            .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn retries_ami_dhcp_disable_with_two_etag_protected_patches() {
        let server = MockServer::start().await;
        let interface = "/redfish/v1/Managers/BMC/EthernetInterfaces/eth0";
        let network = StaticNetwork {
            address: Ipv4Addr::new(10, 10, 1, 9),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 10, 1, 1),
        };

        Mock::given(method("GET"))
            .and(path(interface))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "Id": "eth0" }))
                    .insert_header("etag", "\"resource-version-1\""),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(interface))
            .and(header("if-match", "\"resource-version-1\""))
            .and(body_json(static_ipv4_payload(&network)))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "@Message.ExtendedInfo": [{
                        "MessageId": "SyncAgent.1.0.DisableDHCPv4"
                    }]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(interface))
            .and(header("if-match", "\"resource-version-1\""))
            .and(body_json(dhcpv4_disable_payload()))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(interface))
            .and(header("if-match", "\"resource-version-1\""))
            .and(body_json(static_addresses_payload(&network)))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        client
            .configure_static_ipv4(interface, &network)
            .await
            .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn retries_ami_different_ip_series_by_writing_static_before_disabling_dhcp() {
        let server = MockServer::start().await;
        let interface = "/redfish/v1/Managers/BMC/EthernetInterfaces/eth0";
        let network = StaticNetwork {
            address: Ipv4Addr::new(10, 10, 1, 31),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 10, 1, 254),
        };

        Mock::given(method("GET"))
            .and(path(interface))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "Id": "eth0" }))
                    .insert_header("etag", "\"resource-version-1\""),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(interface))
            .and(header("if-match", "\"resource-version-1\""))
            .and(body_json(static_ipv4_payload(&network)))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "@Message.ExtendedInfo": [{
                        "MessageId": "Ami.1.0.DifferentIpSeries"
                    }]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(interface))
            .and(header("if-match", "\"resource-version-1\""))
            .and(body_json(static_addresses_payload(&network)))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(interface))
            .and(header("if-match", "\"resource-version-1\""))
            .and(body_json(dhcpv4_disable_payload()))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        client
            .configure_static_ipv4(interface, &network)
            .await
            .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn uses_change_password_action_when_bmc_requires_it() {
        let server = MockServer::start().await;
        mock_discovery(&server, true, true).await;
        Mock::given(method("POST"))
            .and(path(
                "/redfish/v1/AccountService/Accounts/admin/Actions/ManagerAccount.ChangePassword",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let inventory = client.discover().await.unwrap();
        client
            .change_password(&inventory.account, "new-password")
            .await
            .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn changes_ami_first_login_password_only_after_matching_public_api_signature() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/source.min.js"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("url:\"/api/session\";url:\"/api/updatenew_password\""),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/session"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-cookie", "QSESSIONID=opaque; HttpOnly")
                    .set_body_json(json!({
                        "passwordStatus": 1,
                        "CSRFToken": "opaque-csrf-token"
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/updatenew_password"))
            .and(header("cookie", "QSESSIONID=opaque"))
            .and(header("x-csrftoken", "opaque-csrf-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "code": 0 })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/session"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client = AmiWebFirstLoginClient::new_for_mock(Url::parse(&server.uri()).unwrap());
        assert!(client.supported().await.unwrap());
        client.reset_password(&credentials()).await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn refuses_ami_bootstrap_when_the_public_signature_is_missing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/source.min.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string("unrelated javascript"))
            .mount(&server)
            .await;

        let client = AmiWebFirstLoginClient::new_for_mock(Url::parse(&server.uri()).unwrap());
        assert!(!client.supported().await.unwrap());
        assert!(matches!(
            client.reset_password(&credentials()).await,
            Err(RedfishError::AmiWebBootstrapUnsupported)
        ));
    }

    #[test]
    fn static_ipv4_payload_disables_dhcp_and_preserves_gateway() {
        let payload = static_ipv4_payload(&StaticNetwork {
            address: Ipv4Addr::new(192, 168, 20, 50),
            prefix: 24,
            gateway: Ipv4Addr::new(192, 168, 20, 1),
        });

        assert_eq!(payload["DHCPv4"]["DHCPEnabled"], false);
        assert_eq!(
            payload["IPv4StaticAddresses"][0]["Address"],
            "192.168.20.50"
        );
        assert_eq!(
            payload["IPv4StaticAddresses"][0]["SubnetMask"],
            "255.255.255.0"
        );
        assert_eq!(payload["IPv4StaticAddresses"][0]["Gateway"], "192.168.20.1");
    }

    #[test]
    fn extracts_only_a_standard_redfish_message_id() {
        let body = json!({
            "error": {
                "code": "Base.1.17.GeneralError",
                "@Message.ExtendedInfo": [{
                    "MessageId": "Base.1.17.PropertyNotWritable",
                    "Message": "This text is deliberately not retained."
                }]
            }
        });
        assert_eq!(
            redfish_message_id(&body).as_deref(),
            Some("Base.1.17.PropertyNotWritable")
        );
    }

    #[test]
    fn ignores_nonstandard_redfish_error_text() {
        let body = json!({
            "error": {
                "code": "arbitrary error response with whitespace",
                "@Message.ExtendedInfo": [{ "MessageId": "also invalid!" }]
            }
        });
        assert_eq!(redfish_message_id(&body), None);
    }

    #[test]
    fn normalizes_colon_separated_certificate_fingerprint() {
        let fingerprint = CertificateFingerprint::parse(
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        )
        .unwrap();
        assert_eq!(
            fingerprint.sha256,
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
    }

    #[test]
    fn rejects_invalid_certificate_fingerprint() {
        assert!(matches!(
            CertificateFingerprint::parse("not-a-fingerprint"),
            Err(RedfishError::InvalidCertificateFingerprint)
        ));
    }
}
