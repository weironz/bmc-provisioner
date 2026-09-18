use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use reqwest::{
    Response, StatusCode, Url,
    header::{COOKIE, ETAG, HeaderValue, IF_MATCH, SET_COOKIE},
};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::TlsConnector;

use crate::model::{Credentials, StaticNetwork};

mod gpu;
mod identity;
/// Prefer an actual current reading; limits, averages and HGX-only power are not substitutes.
fn current_chassis_power(resource: &Value) -> Option<f64> {
    let entry = resource.get("PowerControl")?.as_array()?.first()?;
    entry
        .get("PowerConsumedWatts")
        .and_then(number_as_f64)
        .or_else(|| {
            entry
                .pointer("/PowerMetrics/CurConsumedWatts")
                .and_then(number_as_f64)
        })
        .filter(|watts| watts.is_finite() && *watts >= 0.0)
}
pub use gpu::GpuTelemetry;

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
    pub dhcp_v4_enabled: Option<bool>,
    pub ipv4_static_addresses: Vec<StaticIpv4Address>,
    pub link_status: Option<String>,
}

/// Operator-friendly power intents.  Firmware-specific Redfish ResetType values are resolved
/// only after reading the selected ComputerSystem's AllowableValues.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerAction {
    On,
    Shutdown,
    Restart,
    ForceOff,
    ForceRestart,
    PowerCycle,
}

/// Read-only power capability returned by a BMC's ComputerSystem resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PowerStatus {
    pub system_uri: String,
    pub power_state: Option<String>,
    pub supported_actions: Vec<PowerAction>,
}

/// A compact inventory and health summary assembled from standard Redfish resources. The B300
/// layout is handled explicitly: it has both an HGX baseboard and a host `System_0`; only the
/// latter contains the server CPUs, DDR memory and storage inventory. Optional values stay absent
/// when firmware does not publish the corresponding resource; callers must never mistake a
/// missing metric for zero.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetrySnapshot {
    pub system_uri: String,
    pub name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub bmc_mac: Option<String>,
    pub power_state: Option<String>,
    pub health: Option<String>,
    pub power_watts: Option<f64>,
    pub temperature_celsius: Option<f64>,
    pub cpu: CpuTelemetry,
    pub memory: MemoryTelemetry,
    pub storage: StorageTelemetry,
    pub gpu: GpuTelemetry,
    pub hardware: HardwareTelemetry,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareTelemetry {
    pub fans: Vec<Value>,
    pub power_supplies: Vec<Value>,
    pub drives: Vec<Value>,
    pub network_ports: Vec<Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CpuTelemetry {
    pub packages: usize,
    pub cores: Option<u64>,
    pub threads: Option<u64>,
    pub model: Option<String>,
    pub health: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryTelemetry {
    pub modules: usize,
    pub capacity_mib: Option<u64>,
    pub health: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageTelemetry {
    pub drives: usize,
    pub capacity_bytes: Option<u64>,
    pub health: Option<String>,
}

/// A successful reset request. Redfish may apply it asynchronously, so callers should refresh
/// PowerStatus rather than assuming the immediately returned state has already changed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PowerCommandResult {
    pub system_uri: String,
    pub requested_action: PowerAction,
    pub reset_type: String,
}

/// The address details returned by a Redfish EthernetInterface for a static IPv4 setting.
/// All fields except the address are optional because several BMC implementations omit them.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticIpv4Address {
    pub address: Ipv4Addr,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
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
    tokio::time::timeout(Duration::from_millis(3500), async {
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
    })
    .await
    .map_err(|_| {
        RedfishError::CertificateProbe(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "certificate probe timed out",
        ))
    })?
}

/// Redfish client using HTTP Basic authentication. Certificate validation remains enabled.
#[derive(Clone)]
pub struct RedfishClient {
    base_url: Url,
    client: reqwest::Client,
    fast_verify_client: reqwest::Client,
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
        let fast_verify_client = https_client_with_timeout(fingerprint, Duration::from_secs(3))?;
        Self::from_clients(base_url, credentials, client, fast_verify_client)
    }

    pub fn new(base_url: Url, credentials: &Credentials) -> Result<Self, RedfishError> {
        if base_url.scheme() != "https" {
            return Err(RedfishError::HttpsRequired);
        }
        if base_url.host_str().is_none() {
            return Err(RedfishError::MissingHost);
        }
        let client = https_client(None)?;
        let fast_verify_client = https_client_with_timeout(None, Duration::from_secs(3))?;
        Self::from_clients(base_url, credentials, client, fast_verify_client)
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
            fast_verify_client: reqwest::Client::new(),
            username: credentials.username.clone(),
            password: credentials.current_password.clone(),
        }
    }

    fn from_clients(
        base_url: Url,
        credentials: &Credentials,
        client: reqwest::Client,
        fast_verify_client: reqwest::Client,
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
            fast_verify_client,
            username: credentials.username.clone(),
            password: credentials.current_password.clone(),
        })
    }

    /// Recreate authentication after an account password has changed.
    pub fn with_password(&self, password: String) -> Self {
        Self {
            base_url: self.base_url.clone(),
            client: self.client.clone(),
            fast_verify_client: self.fast_verify_client.clone(),
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
            fast_verify_client: self.fast_verify_client.clone(),
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
                    .iter()
                    .filter_map(|address| address.address)
                    .collect(),
                dhcp_v4_enabled: interface.dhcp_v4.and_then(|dhcp_v4| dhcp_v4.dhcp_enabled),
                ipv4_static_addresses: interface
                    .ipv4_static_addresses
                    .into_iter()
                    .filter_map(|entry| {
                        entry.address.map(|address| StaticIpv4Address {
                            address,
                            subnet_mask: entry.subnet_mask,
                            gateway: entry.gateway,
                        })
                    })
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

    /// Discover the first standard ComputerSystem exposed by this BMC and report only the
    /// actions that its own AllowableValues permit. This keeps a B300 implementation safe while
    /// naturally declining unsupported operations on other firmware.
    pub async fn power_status(&self) -> Result<PowerStatus, RedfishError> {
        let system = self.power_system().await?;
        Ok(PowerStatus {
            system_uri: system.uri,
            power_state: system.power_state,
            supported_actions: supported_power_actions(&system.allowable_reset_types),
        })
    }

    /// Request a power transition using the vendor-advertised ComputerSystem.Reset target.
    /// Never construct an action URI or blindly send a B300 ResetType: both come from Redfish.
    pub async fn set_power(&self, action: PowerAction) -> Result<PowerCommandResult, RedfishError> {
        let system = self.power_system().await?;
        let reset_type = select_reset_type(action, &system.allowable_reset_types)
            .ok_or(RedfishError::UnsupportedPowerAction(action))?;
        let target = system
            .reset_target
            .ok_or(RedfishError::NoPowerResetAction)?;
        self.send_json(
            reqwest::Method::POST,
            &target,
            json!({ "ResetType": reset_type }),
        )
        .await?;
        Ok(PowerCommandResult {
            system_uri: system.uri,
            requested_action: action,
            reset_type: reset_type.to_owned(),
        })
    }

    /// Read the hardware summary used by the fleet console. The root and selected
    /// ComputerSystem are required, while child collections are deliberately best-effort: Redfish
    /// implementations frequently omit Storage, Chassis/Power, or Thermal resources.
    pub async fn telemetry(&self) -> Result<TelemetrySnapshot, RedfishError> {
        self.telemetry_with_model_hint(None).await
    }

    pub async fn telemetry_with_model_hint(
        &self,
        model_hint: Option<&str>,
    ) -> Result<TelemetrySnapshot, RedfishError> {
        let root: ServiceRoot = self.get_json("/redfish/v1/").await?;
        let systems = root.systems.ok_or(RedfishError::NoComputerSystem)?;
        let systems: Collection = self.get_json(&systems.odata_id).await?;
        let b300_layout = systems
            .members
            .iter()
            .any(|member| member.odata_id.ends_with("/HGX_Baseboard_0"));
        let system = selected_system(&systems)?;
        let resource: Value = self.get_json(&system.odata_id).await?;

        // Collect core identity and whole-server readings before optional drive/GPU walks.
        let (model, serial_number, bmc_mac) = self.hardware_identity(&resource, model_hint).await;
        let (power_watts, temperature_celsius, mut hardware) = if b300_layout {
            self.b300_environment().await
        } else {
            let chassis = self
                .collection_values(root.chassis.as_ref().map(|link| link.odata_id.as_str()))
                .await;
            self.chassis_environment(&chassis).await
        };
        // Read accelerator metrics before optional disk endpoints: some AMI NVMe handlers
        // stall and temporarily exhaust firmware authentication/session capacity.
        let gpu = self
            .gpu_telemetry(&systems, &system.odata_id, &resource)
            .await;

        let (processors, memory, storage) = if b300_layout {
            // AMI's B300 BMC can stall when dozens of individual processor or DIMM resources
            // are read serially. It supports standard expansion, which keeps each collection to
            // one bounded request and avoids overwhelming its small Redfish session pool.
            tokio::join!(
                self.expanded_collection_values(resource_link(&resource, "Processors")),
                self.expanded_collection_values(resource_link(&resource, "Memory")),
                self.expanded_collection_values(resource_link(&resource, "Storage")),
            )
        } else {
            (
                self.collection_values(resource_link(&resource, "Processors"))
                    .await,
                self.collection_values(resource_link(&resource, "Memory"))
                    .await,
                self.collection_values(resource_link(&resource, "Storage"))
                    .await,
            )
        };
        let drive_links = link_array(&storage, "Drives");
        let drives = if b300_layout {
            self.resources_with_limit(drive_links, 3).await
        } else {
            self.resources(drive_links).await
        };
        let host_processors = only_cpu_processors(&processors);
        let host_memory = only_host_memory(&memory);

        let cpu_cores = sum_u64(&host_processors, "TotalCores");
        let cpu_threads = sum_u64(&host_processors, "TotalThreads");
        let memory_capacity = sum_u64(&host_memory, "CapacityMiB").or_else(|| {
            resource
                .pointer("/MemorySummary/TotalSystemMemoryGiB")
                .and_then(number_as_u64)
                .and_then(|gib| gib.checked_mul(1024))
        });
        let storage_capacity = sum_u64(&drives, "CapacityBytes");
        hardware.drives = drives.iter().map(|drive| json!({
            "name": drive.get("Name"), "model": drive.get("Model"),
            "health": drive.pointer("/Status/Health"), "state": drive.pointer("/Status/State"),
            "capacityBytes": drive.get("CapacityBytes"),
            "lifeLeftPercent": drive.get("PredictedMediaLifeLeftPercent"),
            "failurePredicted": drive.get("FailurePredicted")
        })).collect();
        if let Some(uri) = resource_link(&resource, "EthernetInterfaces") {
            let ports = self.collection_values(Some(uri)).await;
            hardware.network_ports = ports
                .iter()
                .map(|port| {
                    json!({
                        "name": port.get("Name"), "linkStatus": port.get("LinkStatus"),
                        "speedMbps": port.get("SpeedMbps"), "mac": port.get("MACAddress"),
                        "health": port.pointer("/Status/Health")
                    })
                })
                .collect();
        }

        Ok(TelemetrySnapshot {
            system_uri: system.odata_id.clone(),
            name: string_field(&resource, "Name"),
            manufacturer: string_field(&resource, "Manufacturer"),
            model,
            serial_number,
            bmc_mac,
            power_state: string_field(&resource, "PowerState"),
            health: status_health(&[resource.clone()]),
            power_watts,
            temperature_celsius,
            gpu,
            hardware,
            cpu: CpuTelemetry {
                packages: host_processors.len().max(
                    resource
                        .pointer("/ProcessorSummary/Count")
                        .and_then(number_as_u64)
                        .unwrap_or_default() as usize,
                ),
                cores: cpu_cores,
                threads: cpu_threads,
                model: host_processors
                    .iter()
                    .find_map(|processor| string_field(processor, "Model"))
                    .or_else(|| {
                        resource
                            .pointer("/ProcessorSummary/Model")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    }),
                health: status_health(&host_processors),
            },
            memory: MemoryTelemetry {
                modules: host_memory.len(),
                capacity_mib: memory_capacity,
                health: status_health(&host_memory),
            },
            storage: StorageTelemetry {
                drives: drives.len(),
                capacity_bytes: storage_capacity,
                health: status_health(&drives),
            },
        })
    }

    async fn power_system(&self) -> Result<PowerSystem, RedfishError> {
        let root: ServiceRoot = self.get_json("/redfish/v1/").await?;
        let systems = root.systems.ok_or(RedfishError::NoComputerSystem)?;
        let systems: Collection = self.get_json(&systems.odata_id).await?;
        let system = selected_system(&systems)?;
        let response: ComputerSystem = self.get_json(&system.odata_id).await?;
        // Log the full Actions structure to diagnose B300
        tracing::debug!(
            "BMC ComputerSystem raw Actions: {}",
            serde_json::to_string_pretty(&response.actions).unwrap_or_else(|_| "{}".to_string())
        );

        // Only expose actions the selected host actually declares.
        let reset = response.reset_action();
        let mut allowable_types = reset
            .as_ref()
            .map(|action| action.allowable_reset_types.clone())
            .unwrap_or_default();
        // Redfish deprecated the inline `ResetType@Redfish.AllowableValues` annotation in favor
        // of a separate ActionInfo resource. Firmware that publishes only the latter would
        // otherwise look like a controller that supports no power operation at all.
        if allowable_types.is_empty()
            && let Some(action_info) = reset
                .as_ref()
                .and_then(|action| action.action_info_uri.as_deref())
        {
            match self.get_json::<ActionInfo>(action_info).await {
                Ok(info) => allowable_types = info.reset_type_allowable_values(),
                // An unreadable ActionInfo is not a reason to fail the whole status read: the
                // caller still gets PowerState, and simply no action is offered.
                Err(error) => {
                    tracing::debug!("could not read ResetType ActionInfo {action_info}: {error}")
                }
            }
        }
        tracing::debug!(
            "BMC ComputerSystem: uri={}, power_state={:?}, reset_target={:?}, allowable_reset_types={:?}",
            system.odata_id,
            response.power_state,
            reset.as_ref().map(|a| &a.target),
            allowable_types
        );
        Ok(PowerSystem {
            uri: system.odata_id.clone(),
            power_state: response.power_state,
            reset_target: reset.as_ref().map(|action| action.target.clone()),
            allowable_reset_types: allowable_types,
        })
    }

    async fn collection_values(&self, resource: Option<&str>) -> Vec<Value> {
        let Some(resource) = resource else {
            return Vec::new();
        };
        let collection = match self.get_json::<Collection>(resource).await {
            Ok(collection) => collection,
            Err(error) => {
                tracing::debug!(resource, error = %error, "optional Redfish collection could not be read");
                return Vec::new();
            }
        };
        self.resources(
            collection
                .members
                .into_iter()
                .map(|member| member.odata_id)
                .collect(),
        )
        .await
    }

    /// Read the immediate collection members in one request. B300 supports `$expand` on its
    /// host collections and this is intentionally used only for its detected HGX layout.
    async fn expanded_collection_values(&self, resource: Option<&str>) -> Vec<Value> {
        let Some(resource) = resource else {
            return Vec::new();
        };
        let expanded = format!("{resource}?$expand=*($levels=1)");
        match self.get_json::<Value>(&expanded).await {
            Ok(collection) => collection
                .get("Members")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            Err(error) => {
                tracing::debug!(resource, error = %error, "expanded B300 Redfish collection could not be read");
                Vec::new()
            }
        }
    }

    async fn resources(&self, resources: Vec<String>) -> Vec<Value> {
        let mut values = Vec::with_capacity(resources.len());
        for resource in resources {
            match self.get_json::<Value>(&resource).await {
                Ok(value) => values.push(value),
                Err(error) => {
                    tracing::debug!(resource, error = %error, "optional Redfish resource could not be read")
                }
            }
        }
        values
    }

    /// BMC controllers have a small HTTP/session budget. A bounded fan-out gathers storage
    /// details without turning a ten-drive system into a long serial scrape or a 403 storm.
    async fn resources_with_limit(&self, resources: Vec<String>, limit: usize) -> Vec<Value> {
        let mut pending = resources.into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        let mut values = Vec::new();
        for _ in 0..limit.max(1) {
            let Some(resource) = pending.next() else {
                break;
            };
            let client = self.clone();
            tasks.spawn(async move { client.optional_inventory_value(&resource).await });
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(value)) = result {
                values.push(value);
            }
            if let Some(resource) = pending.next() {
                let client = self.clone();
                tasks.spawn(async move { client.optional_inventory_value(&resource).await });
            }
        }
        values
    }

    async fn optional_inventory_value(&self, resource: &str) -> Option<Value> {
        match tokio::time::timeout(Duration::from_secs(4), self.optional_value(resource)).await {
            Ok(value) => value,
            Err(_) => {
                tracing::debug!(
                    resource,
                    "optional inventory read exceeded four-second budget"
                );
                None
            }
        }
    }

    async fn chassis_environment(
        &self,
        chassis: &[Value],
    ) -> (Option<f64>, Option<f64>, HardwareTelemetry) {
        let Some(chassis) = chassis.first() else {
            return (None, None, HardwareTelemetry::default());
        };
        let power = match resource_link(chassis, "Power") {
            Some(uri) => match self.get_json::<Value>(uri).await {
                Ok(value) => Some(value),
                Err(error) => {
                    tracing::debug!(resource = uri, error = %error, "optional Redfish power resource could not be read");
                    None
                }
            },
            None => None,
        };
        let thermal = match resource_link(chassis, "Thermal") {
            Some(uri) => match self.get_json::<Value>(uri).await {
                Ok(value) => Some(value),
                Err(error) => {
                    tracing::debug!(resource = uri, error = %error, "optional Redfish thermal resource could not be read");
                    None
                }
            },
            None => None,
        };
        let power_watts = power.as_ref().and_then(current_chassis_power);
        let temperature_celsius = thermal.as_ref().and_then(|resource| {
            resource
                .get("Temperatures")
                .and_then(Value::as_array)
                .and_then(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.get("ReadingCelsius").and_then(number_as_f64))
                        .max_by(f64::total_cmp)
                })
        });
        (
            power_watts,
            temperature_celsius,
            hardware_environment(power.as_ref(), thermal.as_ref()),
        )
    }

    /// HGX EnvironmentMetrics measures the accelerator baseboard, not the whole server.
    /// Whole-server power and thermals are published by the BMC chassis.
    async fn b300_environment(&self) -> (Option<f64>, Option<f64>, HardwareTelemetry) {
        let (thermal, power) = tokio::join!(
            self.optional_value("/redfish/v1/Chassis/BMC_0/Thermal"),
            self.optional_value("/redfish/v1/Chassis/BMC_0/Power"),
        );
        let power_watts = power.as_ref().and_then(current_chassis_power);
        let temperature_celsius = thermal.as_ref().and_then(|resource| {
            resource
                .get("Temperatures")
                .and_then(Value::as_array)
                .and_then(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.get("ReadingCelsius").and_then(number_as_f64))
                        .max_by(f64::total_cmp)
                })
        });
        (
            power_watts,
            temperature_celsius,
            hardware_environment(power.as_ref(), thermal.as_ref()),
        )
    }

    async fn optional_value(&self, resource: &str) -> Option<Value> {
        match self.get_json(resource).await {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::debug!(resource, error = %error, "optional Redfish resource could not be read");
                None
            }
        }
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

    /// A deliberately short authenticated probe for a BMC that is expected to be temporarily
    /// unavailable while applying a network change. Normal discovery keeps the firmware's
    /// regular request behavior; only this retry loop uses the three-second deadline.
    pub async fn verify_connection_fast(&self) -> Result<(), RedfishError> {
        let url = self.resource_url("/redfish/v1/")?;
        let response = self
            .fast_verify_client
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(RedfishError::Request)?;
        let response = ensure_success(response).await?;
        let _: ServiceRoot = response.json().await.map_err(RedfishError::Decode)?;
        Ok(())
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        resource: &str,
    ) -> Result<T, RedfishError> {
        let read_lock = self.read_lock();
        let _guard = read_lock.lock().await;
        let url = self.resource_url(resource)?;
        tracing::debug!(resource, "reading Redfish resource");
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
    https_client_with_options(fingerprint, None)
}

fn https_client_with_timeout(
    fingerprint: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::Client, RedfishError> {
    https_client_with_options(fingerprint, Some(timeout))
}

fn https_client_with_options(
    fingerprint: Option<&str>,
    timeout: Option<Duration>,
) -> Result<reqwest::Client, RedfishError> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        // Monitoring must eventually return control to its automatic scheduler. A BMC can accept
        // TLS and then leave an individual Redfish resource hanging indefinitely.
        .timeout(timeout.unwrap_or(Duration::from_secs(15)));
    match fingerprint {
        Some(fingerprint) => {
            let fingerprint = CertificateFingerprint::parse(fingerprint)?;
            builder
                .use_preconfigured_tls(pinned_tls_config(Some(fingerprint)))
                .build()
                .map_err(RedfishError::Client)
        }
        None => builder.build().map_err(RedfishError::Client),
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

fn supported_power_actions(allowable_reset_types: &[String]) -> Vec<PowerAction> {
    let result: Vec<PowerAction> = [
        PowerAction::On,
        PowerAction::Shutdown,
        PowerAction::Restart,
        PowerAction::ForceOff,
        PowerAction::ForceRestart,
        PowerAction::PowerCycle,
    ]
    .into_iter()
    .filter(|action| select_reset_type(*action, allowable_reset_types).is_some())
    .collect();
    tracing::debug!(
        "Mapped allowable_reset_types={:?} to supported_actions={:?}",
        allowable_reset_types,
        result
    );
    result
}

/// Graceful and forced operations are separate operator choices; never escalate implicitly.
/// `PushPowerButton` is deliberately never used: it toggles rather than reaching a known state.
fn select_reset_type(action: PowerAction, allowable_reset_types: &[String]) -> Option<&str> {
    let preferred: &[&str] = match action {
        PowerAction::On => &["On", "ForceOn"],
        PowerAction::Shutdown => &["GracefulShutdown"],
        PowerAction::Restart => &["GracefulRestart"],
        PowerAction::ForceOff => &["ForceOff"],
        PowerAction::ForceRestart => &["ForceRestart"],
        PowerAction::PowerCycle => &["PowerCycle"],
    };
    preferred.iter().find_map(|candidate| {
        allowable_reset_types
            .iter()
            .find(|allowed| allowed.eq_ignore_ascii_case(candidate))
            .map(String::as_str)
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
    #[error("Redfish did not expose a ComputerSystem resource")]
    NoComputerSystem,
    #[error("Redfish ComputerSystem does not expose a reset action")]
    NoPowerResetAction,
    #[error("this BMC does not support the requested {0:?} power action")]
    UnsupportedPowerAction(PowerAction),
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
    #[serde(rename = "Systems", default)]
    systems: Option<Link>,
    #[serde(rename = "Chassis", default)]
    chassis: Option<Link>,
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

/// Select the host ComputerSystem when a BMC publishes auxiliary systems as well. NVIDIA HGX
/// controllers list `HGX_Baseboard_0` before their actual host `System_0`; choosing the first
/// member would incorrectly turn GPU/HBM inventory into CPU/DDR telemetry.
fn selected_system(systems: &Collection) -> Result<&Link, RedfishError> {
    systems
        .members
        .iter()
        .find(|member| member.odata_id.ends_with("/System_0"))
        .or_else(|| systems.members.first())
        .ok_or(RedfishError::NoComputerSystem)
}

fn only_cpu_processors(processors: &[Value]) -> Vec<Value> {
    let cpu_processors: Vec<Value> = processors
        .iter()
        .filter(|processor| string_field(processor, "ProcessorType").as_deref() == Some("CPU"))
        .cloned()
        .collect();
    if cpu_processors.is_empty() {
        processors.to_vec()
    } else {
        cpu_processors
    }
}

fn only_host_memory(memory: &[Value]) -> Vec<Value> {
    let host_memory: Vec<Value> = memory
        .iter()
        .filter(|module| string_field(module, "MemoryDeviceType").as_deref() != Some("HBM"))
        .cloned()
        .collect();
    if host_memory.is_empty() {
        memory.to_vec()
    } else {
        host_memory
    }
}

fn hardware_environment(power: Option<&Value>, thermal: Option<&Value>) -> HardwareTelemetry {
    let fans = thermal.and_then(|v| v.get("Fans")).and_then(Value::as_array)
        .map(|fans| fans.iter().map(|fan| json!({
            "name": fan.get("Name"), "reading": fan.get("Reading"), "units": fan.get("ReadingUnits"),
            "health": fan.pointer("/Status/Health"), "state": fan.pointer("/Status/State")
        })).collect()).unwrap_or_default();
    let power_supplies = power.and_then(|v| v.get("PowerSupplies")).and_then(Value::as_array)
        .map(|supplies| supplies.iter().map(|supply| json!({
            "name": supply.get("Name"), "model": supply.get("Model"),
            "health": supply.pointer("/Status/Health"), "state": supply.pointer("/Status/State"),
            "inputWatts": supply.get("PowerInputWatts"), "outputWatts": supply.get("PowerOutputWatts"),
            "capacityWatts": supply.get("PowerCapacityWatts")
        })).collect()).unwrap_or_default();
    HardwareTelemetry {
        fans,
        power_supplies,
        ..Default::default()
    }
}

fn resource_link<'a>(resource: &'a Value, field: &str) -> Option<&'a str> {
    resource.get(field).and_then(|link| {
        link.as_str()
            .or_else(|| link.get("@odata.id").and_then(Value::as_str))
    })
}

fn link_array(resources: &[Value], field: &str) -> Vec<String> {
    resources
        .iter()
        .flat_map(|resource| {
            resource
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|link| {
                    link.as_str()
                        .or_else(|| link.get("@odata.id").and_then(Value::as_str))
                        .map(ToOwned::to_owned)
                })
        })
        .collect()
}

fn string_field(resource: &Value, field: &str) -> Option<String> {
    resource
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn number_as_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|number| *number >= 0.0)
            .map(|number| number as u64)
    })
}

fn number_as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_u64().map(|number| number as f64))
}

fn sum_u64(resources: &[Value], field: &str) -> Option<u64> {
    let mut found = false;
    let total = resources
        .iter()
        .filter_map(|resource| {
            resource
                .get(field)
                .and_then(number_as_u64)
                .inspect(|_| found = true)
        })
        .sum();
    found.then_some(total)
}

fn status_health(resources: &[Value]) -> Option<String> {
    let values: Vec<&str> = resources
        .iter()
        .filter_map(|resource| resource.pointer("/Status/Health").and_then(Value::as_str))
        .collect();
    values
        .iter()
        .find(|health| !matches!(**health, "OK" | "Unknown"))
        .or_else(|| values.first())
        .map(|health| (*health).to_owned())
}

#[derive(Deserialize)]
struct Manager {
    #[serde(rename = "EthernetInterfaces")]
    ethernet_interfaces: Option<Link>,
}

struct PowerSystem {
    uri: String,
    power_state: Option<String>,
    reset_target: Option<String>,
    allowable_reset_types: Vec<String>,
}

#[derive(Deserialize)]
struct ComputerSystem {
    #[serde(rename = "PowerState")]
    power_state: Option<String>,
    #[serde(rename = "Actions", default)]
    actions: Value,
}

struct ResetAction {
    target: String,
    allowable_reset_types: Vec<String>,
    /// Set when the firmware publishes its allowable values in a separate ActionInfo resource
    /// instead of the deprecated inline annotation.
    action_info_uri: Option<String>,
}

impl ComputerSystem {
    fn reset_action(&self) -> Option<ResetAction> {
        // Try standard Redfish format: Actions["#ComputerSystem.Reset"]
        if let Some(action) = self.actions.get("#ComputerSystem.Reset") {
            if let Some(target) = action.get("target").and_then(Value::as_str) {
                let allowable_reset_types = action
                    .get("ResetType@Redfish.AllowableValues")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                return Some(ResetAction {
                    target: target.to_owned(),
                    allowable_reset_types,
                    action_info_uri: action_info_uri(action),
                });
            }
        }

        // Fallback: try Oem vendor extensions for B300-like implementations
        // Some BMC implementations put reset actions under Oem paths
        if let Some(oem) = self.actions.get("Oem") {
            tracing::debug!("ComputerSystem has Oem actions, checking for vendor reset actions");
            // Log available OEM actions for debugging
            if let Some(obj) = oem.as_object() {
                tracing::debug!(
                    "Available Oem vendors: {:?}",
                    obj.keys().collect::<Vec<_>>()
                );
            }
        }

        None
    }
}

/// `@Redfish.ActionInfo` is specified as a URI string. The object form is also accepted because
/// some implementations serialize it the way they serialize a resource link.
fn action_info_uri(action: &Value) -> Option<String> {
    let value = action.get("@Redfish.ActionInfo")?;
    value
        .as_str()
        .or_else(|| value.get("@odata.id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

/// The standard resource that replaced inline action annotations. Only the `ResetType`
/// parameter is read; nothing here is vendor-specific.
#[derive(Deserialize)]
struct ActionInfo {
    #[serde(rename = "Parameters", default)]
    parameters: Vec<ActionParameter>,
}

#[derive(Deserialize)]
struct ActionParameter {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "AllowableValues", default)]
    allowable_values: Vec<String>,
}

impl ActionInfo {
    fn reset_type_allowable_values(self) -> Vec<String> {
        self.parameters
            .into_iter()
            .find(|parameter| parameter.name.as_deref() == Some("ResetType"))
            .map(|parameter| parameter.allowable_values)
            .unwrap_or_default()
    }
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
    #[serde(rename = "DHCPv4")]
    dhcp_v4: Option<DhcpV4>,
    #[serde(rename = "IPv4StaticAddresses", default)]
    ipv4_static_addresses: Vec<Ipv4Address>,
    #[serde(rename = "LinkStatus")]
    link_status: Option<String>,
}

#[derive(Deserialize)]
struct Ipv4Address {
    #[serde(rename = "Address")]
    address: Option<Ipv4Addr>,
    #[serde(rename = "SubnetMask")]
    subnet_mask: Option<Ipv4Addr>,
    #[serde(rename = "Gateway")]
    gateway: Option<Ipv4Addr>,
}

#[derive(Deserialize)]
struct DhcpV4 {
    #[serde(rename = "DHCPEnabled")]
    dhcp_enabled: Option<bool>,
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

    #[tokio::test]
    async fn uses_computer_system_reset_values_advertised_by_the_bmc() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "AccountService": { "@odata.id": "/redfish/v1/AccountService" },
                "Managers": { "@odata.id": "/redfish/v1/Managers" },
                "Systems": { "@odata.id": "/redfish/v1/Systems" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Members": [{ "@odata.id": "/redfish/v1/Systems/1" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "PowerState": "Off",
                "Actions": {
                    "#ComputerSystem.Reset": {
                        "target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
                        "ResetType@Redfish.AllowableValues": ["On", "ForceOff", "ForceRestart"]
                    }
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"))
            .and(body_json(json!({ "ResetType": "ForceRestart" })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let status = client.power_status().await.unwrap();
        assert_eq!(status.power_state.as_deref(), Some("Off"));
        assert_eq!(
            status.supported_actions,
            vec![
                PowerAction::On,
                PowerAction::ForceOff,
                PowerAction::ForceRestart
            ]
        );
        // A graceful request must not POST a forced reset, even on forced-only firmware.
        assert!(matches!(
            client.set_power(PowerAction::Restart).await,
            Err(RedfishError::UnsupportedPowerAction(PowerAction::Restart))
        ));
        assert!(matches!(
            client.set_power(PowerAction::Shutdown).await,
            Err(RedfishError::UnsupportedPowerAction(PowerAction::Shutdown))
        ));
        let result = client.set_power(PowerAction::ForceRestart).await.unwrap();
        assert_eq!(result.reset_type, "ForceRestart");
        server.verify().await;
    }

    #[test]
    fn power_intents_do_not_escalate_to_other_reset_types() {
        let cases = [
            (PowerAction::On, "On"),
            (PowerAction::Shutdown, "GracefulShutdown"),
            (PowerAction::Restart, "GracefulRestart"),
            (PowerAction::ForceOff, "ForceOff"),
            (PowerAction::ForceRestart, "ForceRestart"),
            (PowerAction::PowerCycle, "PowerCycle"),
        ];
        for (intent, reset_type) in cases {
            let advertised = vec![reset_type.to_owned()];
            assert_eq!(select_reset_type(intent, &advertised), Some(reset_type));
            for (other_intent, _) in cases {
                if other_intent != intent {
                    assert_eq!(select_reset_type(other_intent, &advertised), None);
                }
            }
        }
        // FullPowerCycle can affect the manager itself and is not an alias for host PowerCycle.
        assert!(
            supported_power_actions(&["FullPowerCycle".into(), "PushPowerButton".into()])
                .is_empty()
        );
    }

    /// Redfish deprecated the inline allowable-values annotation. A BMC that only publishes the
    /// ActionInfo resource still advertises real power capabilities and must not be treated as
    /// a controller without any supported reset.
    #[tokio::test]
    async fn reads_allowable_reset_types_from_a_separate_action_info_resource() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "AccountService": { "@odata.id": "/redfish/v1/AccountService" },
                "Managers": { "@odata.id": "/redfish/v1/Managers" },
                "Systems": { "@odata.id": "/redfish/v1/Systems" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Members": [{ "@odata.id": "/redfish/v1/Systems/Self" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems/Self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "PowerState": "On",
                "Actions": {
                    "#ComputerSystem.Reset": {
                        "target": "/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset",
                        "@Redfish.ActionInfo": "/redfish/v1/Systems/Self/ResetActionInfo"
                    }
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems/Self/ResetActionInfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Parameters": [
                    { "Name": "ResetType", "DataType": "String", "Required": true,
                      "AllowableValues": ["On", "ForceOff", "GracefulShutdown", "PowerCycle"] }
                ]
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset",
            ))
            .and(body_json(json!({ "ResetType": "PowerCycle" })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let status = client.power_status().await.unwrap();
        assert_eq!(
            status.supported_actions,
            vec![
                PowerAction::On,
                PowerAction::Shutdown,
                PowerAction::ForceOff,
                PowerAction::PowerCycle
            ]
        );
        let result = client.set_power(PowerAction::PowerCycle).await.unwrap();
        assert_eq!(result.reset_type, "PowerCycle");
        server.verify().await;
    }

    /// A ComputerSystem that neither inlines allowable values nor points at an ActionInfo must
    /// offer nothing rather than have a ResetType guessed on its behalf.
    #[tokio::test]
    async fn offers_no_power_action_when_the_bmc_declares_no_reset_type() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "AccountService": { "@odata.id": "/redfish/v1/AccountService" },
                "Managers": { "@odata.id": "/redfish/v1/Managers" },
                "Systems": { "@odata.id": "/redfish/v1/Systems" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Members": [{ "@odata.id": "/redfish/v1/Systems/1" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "PowerState": "On",
                "Actions": {
                    "#ComputerSystem.Reset": {
                        "target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"
                    }
                }
            })))
            .mount(&server)
            .await;

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let status = client.power_status().await.unwrap();
        assert_eq!(status.power_state.as_deref(), Some("On"));
        assert!(status.supported_actions.is_empty());
        assert!(matches!(
            client.set_power(PowerAction::On).await,
            Err(RedfishError::UnsupportedPowerAction(PowerAction::On))
        ));
    }

    #[tokio::test]
    async fn reads_standard_hardware_telemetry() {
        let server = MockServer::start().await;
        let root = json!({
            "AccountService": { "@odata.id": "/redfish/v1/AccountService" },
            "Managers": { "@odata.id": "/redfish/v1/Managers" },
            "Systems": { "@odata.id": "/redfish/v1/Systems" },
            "Chassis": { "@odata.id": "/redfish/v1/Chassis" }
        });
        let systems = json!({ "Members": [{ "@odata.id": "/redfish/v1/Systems/1" }] });
        let system = json!({
            "Name": "GPU node 01",
            "Manufacturer": "GreenStor",
            "Model": "B300-8U",
            "SerialNumber": "GS-0001",
            "PowerState": "On",
            "Status": { "Health": "OK" },
            "ProcessorSummary": { "Count": 2, "Model": "fallback" },
            "MemorySummary": { "TotalSystemMemoryGiB": 96 },
            "Processors": { "@odata.id": "/redfish/v1/Systems/1/Processors" },
            "Memory": { "@odata.id": "/redfish/v1/Systems/1/Memory" },
            "Storage": { "@odata.id": "/redfish/v1/Systems/1/Storage" }
        });
        let chassis = json!({ "Members": [{ "@odata.id": "/redfish/v1/Chassis/1" }] });
        let chassis_one = json!({
            "Power": { "@odata.id": "/redfish/v1/Chassis/1/Power" },
            "Thermal": { "@odata.id": "/redfish/v1/Chassis/1/Thermal" }
        });
        let processors = json!({ "Members": [
            { "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0" },
            { "@odata.id": "/redfish/v1/Systems/1/Processors/CPU1" }
        ] });
        let memory = json!({ "Members": [
            { "@odata.id": "/redfish/v1/Systems/1/Memory/DIMM0" },
            { "@odata.id": "/redfish/v1/Systems/1/Memory/DIMM1" }
        ] });
        let storage = json!({ "Members": [{ "@odata.id": "/redfish/v1/Systems/1/Storage/1" }] });
        let storage_one = json!({ "Drives": [
            { "@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/0" },
            { "@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/1" }
        ] });

        for (route, body) in [
            ("/redfish/v1/", root),
            ("/redfish/v1/Systems", systems),
            ("/redfish/v1/Systems/1", system),
            ("/redfish/v1/Chassis", chassis),
            ("/redfish/v1/Chassis/1", chassis_one),
            ("/redfish/v1/Systems/1/Processors", processors),
            ("/redfish/v1/Systems/1/Memory", memory),
            ("/redfish/v1/Systems/1/Storage", storage),
            ("/redfish/v1/Systems/1/Storage/1", storage_one),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }
        for (route, body) in [
            (
                "/redfish/v1/Systems/1/Processors/CPU0",
                json!({ "Model": "AMD EPYC", "TotalCores": 64, "TotalThreads": 128, "Status": { "Health": "OK" } }),
            ),
            (
                "/redfish/v1/Systems/1/Processors/CPU1",
                json!({ "Model": "AMD EPYC", "TotalCores": 64, "TotalThreads": 128, "Status": { "Health": "OK" } }),
            ),
            (
                "/redfish/v1/Systems/1/Memory/DIMM0",
                json!({ "CapacityMiB": 49152, "Status": { "Health": "OK" } }),
            ),
            (
                "/redfish/v1/Systems/1/Memory/DIMM1",
                json!({ "CapacityMiB": 49152, "Status": { "Health": "Warning" } }),
            ),
            (
                "/redfish/v1/Systems/1/Storage/1/Drives/0",
                json!({ "CapacityBytes": 1000, "Status": { "Health": "OK" } }),
            ),
            (
                "/redfish/v1/Systems/1/Storage/1/Drives/1",
                json!({ "CapacityBytes": 2000, "Status": { "Health": "Critical" } }),
            ),
            (
                "/redfish/v1/Chassis/1/Power",
                json!({ "PowerControl": [{ "PowerConsumedWatts": 1875.5 }] }),
            ),
            (
                "/redfish/v1/Chassis/1/Thermal",
                json!({ "Temperatures": [{ "ReadingCelsius": 42.0 }, { "ReadingCelsius": 57.5 }] }),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let telemetry = client.telemetry().await.unwrap();
        assert_eq!(telemetry.name.as_deref(), Some("GPU node 01"));
        assert_eq!(telemetry.power_watts, Some(1875.5));
        assert_eq!(telemetry.temperature_celsius, Some(57.5));
        assert_eq!(telemetry.cpu.packages, 2);
        assert_eq!(telemetry.cpu.cores, Some(128));
        assert_eq!(telemetry.memory.capacity_mib, Some(98_304));
        assert_eq!(telemetry.memory.health.as_deref(), Some("Warning"));
        assert_eq!(telemetry.storage.drives, 2);
        assert_eq!(telemetry.storage.capacity_bytes, Some(3_000));
        assert_eq!(telemetry.storage.health.as_deref(), Some("Critical"));
    }

    #[tokio::test]
    async fn reads_b300_host_inventory_and_whole_server_power() {
        let server = MockServer::start().await;
        let root = json!({
            "AccountService": { "@odata.id": "/redfish/v1/AccountService" },
            "Managers": { "@odata.id": "/redfish/v1/Managers" },
            "Systems": { "@odata.id": "/redfish/v1/Systems" },
            "Chassis": { "@odata.id": "/redfish/v1/Chassis" }
        });
        // The baseboard is deliberately first: this is the layout that previously caused the
        // fleet console to report GPU/HBM inventory as host CPU/DDR inventory.
        let systems = json!({ "Members": [
            { "@odata.id": "/redfish/v1/Systems/HGX_Baseboard_0" },
            { "@odata.id": "/redfish/v1/Systems/System_0" }
        ] });
        let system = json!({
            "Name": "System",
            "Manufacturer": "ASRockRack",
            "Model": "B300 8U16X-GNR2",
            "PowerState": "On",
            "Status": { "Health": "OK" },
            "Processors": { "@odata.id": "/redfish/v1/Systems/System_0/Processors" },
            "Memory": { "@odata.id": "/redfish/v1/Systems/System_0/Memory" },
            "Storage": { "@odata.id": "/redfish/v1/Systems/System_0/Storage" }
        });
        let processors = json!({ "Members": [
            { "@odata.id": "/redfish/v1/Systems/System_0/Processors/CPU_0", "ProcessorType": "CPU", "Model": "Xeon", "TotalCores": 64, "TotalThreads": 128, "Status": { "Health": "OK" } },
            { "@odata.id": "/redfish/v1/Systems/System_0/Processors/CPU_1", "ProcessorType": "CPU", "Model": "Xeon", "TotalCores": 64, "TotalThreads": 128, "Status": { "Health": "OK" } },
            { "@odata.id": "/redfish/v1/Systems/System_0/Processors/GPU_0", "ProcessorType": "GPU", "TotalCores": 9_999 }
        ] });
        let memory = json!({ "Members": [
            { "@odata.id": "/redfish/v1/Systems/System_0/Memory/DIMM_0", "MemoryDeviceType": "DDR5", "CapacityMiB": 98_304, "Status": { "Health": "OK" } },
            { "@odata.id": "/redfish/v1/Systems/System_0/Memory/HBM_0", "MemoryDeviceType": "HBM", "CapacityMiB": 81_920 }
        ] });
        let storage = json!({ "Members": [
            { "@odata.id": "/redfish/v1/Systems/System_0/Storage/1", "Drives": [
                { "@odata.id": "/redfish/v1/Systems/System_0/Storage/1/Drives/NVMe_0" }
            ] }
        ] });

        for (route, body) in [
            ("/redfish/v1/", root),
            ("/redfish/v1/Systems", systems),
            ("/redfish/v1/Systems/System_0", system),
            ("/redfish/v1/Systems/System_0/Processors", processors),
            ("/redfish/v1/Systems/System_0/Memory", memory),
            ("/redfish/v1/Systems/System_0/Storage", storage),
            (
                "/redfish/v1/Chassis/HGX_Chassis_0/EnvironmentMetrics",
                json!({ "PowerWatts": { "Reading": 2420.5 } }),
            ),
            (
                "/redfish/v1/Chassis/BMC_0/Power",
                json!({"PowerControl":[{"PowerConsumedWatts":null,"PowerMetrics":{"CurConsumedWatts":4920,"AverageConsumedWatts":4925}}]}),
            ),
            (
                "/redfish/v1/Chassis/BMC_0/Thermal",
                json!({ "Temperatures": [
                    { "ReadingCelsius": 39.5 },
                    { "ReadingCelsius": 71.0 }
                ] }),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }
        for (route, body) in [(
            "/redfish/v1/Systems/System_0/Storage/1/Drives/NVMe_0",
            json!({ "CapacityBytes": 1_000_000, "Status": { "Health": "OK" } }),
        )] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }

        let client =
            RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials());
        let telemetry = client.telemetry().await.unwrap();
        assert_eq!(telemetry.system_uri, "/redfish/v1/Systems/System_0");
        assert_eq!(telemetry.cpu.packages, 2);
        assert_eq!(telemetry.cpu.cores, Some(128));
        assert_eq!(telemetry.memory.modules, 1);
        assert_eq!(telemetry.memory.capacity_mib, Some(98_304));
        assert_eq!(telemetry.storage.drives, 1);
        assert_eq!(telemetry.storage.capacity_bytes, Some(1_000_000));
        assert_eq!(telemetry.power_watts, Some(4920.0));
        assert_eq!(telemetry.temperature_celsius, Some(71.0));
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
            "IPv4Addresses": [{ "Address": "192.168.1.10" }],
            "DHCPv4": { "DHCPEnabled": false },
            "IPv4StaticAddresses": [{ "Address": "192.168.1.10", "SubnetMask": "255.255.255.0", "Gateway": "192.168.1.1" }],
            "LinkStatus": "LinkUp"
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
        assert_eq!(
            inventory.ethernet_interfaces[0].dhcp_v4_enabled,
            Some(false)
        );
        assert_eq!(
            inventory.ethernet_interfaces[0].ipv4_static_addresses[0].gateway,
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
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
