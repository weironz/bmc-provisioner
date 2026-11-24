use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use bmc_provisioner::redfish::RedfishError;
use serde::{Deserialize, Serialize};
use tokio::{
    task::JoinSet,
    time::{Instant, timeout},
};

use super::{
    ApiError, AppState, ManagedBmc, ManagedPowerStatusResponse, PowerStatus, RedfishClient,
    TelemetrySnapshot, credentials_for_managed_bmc, current_timestamp_seconds, inventory_api_error,
    probe_certificate,
};

const MAX_IN_FLIGHT: usize = 2;
const POWER_TIMEOUT: Duration = Duration::from_secs(20);
const TELEMETRY_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Default)]
pub(super) struct Monitoring {
    devices: tokio::sync::Mutex<HashMap<String, DeviceSample>>,
}

struct DeviceSample {
    device: ManagedBmc,
    power: Option<PowerStatus>,
    power_detail: Option<String>,
    telemetry: Option<TelemetrySnapshot>,
    collected_at: Option<i64>,
    attempted_at: Option<i64>,
    detail: Option<String>,
}

impl DeviceSample {
    fn new(device: ManagedBmc) -> Self {
        Self {
            device,
            power: None,
            power_detail: None,
            telemetry: None,
            collected_at: None,
            attempted_at: None,
            detail: None,
        }
    }
}

fn same_target(a: &ManagedBmc, b: &ManagedBmc) -> bool {
    a.current_ip == b.current_ip
        && a.credential_profile == b.credential_profile
        && a.credential_username == b.credential_username
        && a.credential_updated_at == b.credential_updated_at
        && a.configuration_status != "draft"
        && b.configuration_status != "draft"
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Settings {
    interval_seconds: u64,
}

pub(super) async fn load_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Settings>, ApiError> {
    Ok(Json(Settings {
        interval_seconds: state
            .inventory
            .monitoring_interval()
            .map_err(inventory_api_error)?,
    }))
}

pub(super) async fn save_settings(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<Settings>,
) -> Result<Json<Settings>, ApiError> {
    if !matches!(settings.interval_seconds, 0 | 15 | 30 | 60 | 120) {
        return Err(ApiError::bad_request("unsupported monitoring interval"));
    }
    state
        .inventory
        .save_monitoring_interval(settings.interval_seconds)
        .map_err(inventory_api_error)?;
    Ok(Json(settings))
}

pub(super) async fn cached_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ManagedPowerStatusResponse>>, ApiError> {
    let _edit = state.inventory_edit.lock().await;
    let devices = state.inventory.list().map_err(inventory_api_error)?;
    let samples = state.monitoring.devices.lock().await;
    Ok(Json(
        devices
            .into_iter()
            .map(|managed| {
                let sample = samples
                    .get(&managed.identity)
                    .filter(|entry| same_target(&entry.device, &managed));
                ManagedPowerStatusResponse {
                    power: sample.and_then(|entry| entry.power.clone()),
                    detail: sample
                        .and_then(|entry| entry.power_detail.clone())
                        .or_else(|| managed.last_error.clone()),
                    certificate_fingerprint: None,
                    certificate_trust_required: false,
                    managed,
                }
            })
            .collect(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CachedTelemetry {
    managed: ManagedBmc,
    telemetry: Option<TelemetrySnapshot>,
    collected_at: Option<i64>,
    attempted_at: Option<i64>,
    detail: Option<String>,
}

pub(super) async fn cached_telemetry(
    State(state): State<Arc<AppState>>,
    Path(identity): Path<String>,
) -> Result<Json<CachedTelemetry>, ApiError> {
    let _edit = state.inventory_edit.lock().await;
    let managed = state
        .inventory
        .find(&identity)
        .map_err(inventory_api_error)?
        .ok_or_else(|| ApiError::not_found("managed BMC was not found"))?;
    let samples = state.monitoring.devices.lock().await;
    let sample = samples
        .get(&identity)
        .filter(|entry| same_target(&entry.device, &managed));
    Ok(Json(CachedTelemetry {
        telemetry: sample.and_then(|entry| entry.telemetry.clone()),
        collected_at: sample.and_then(|entry| entry.collected_at),
        attempted_at: sample.and_then(|entry| entry.attempted_at),
        detail: sample.and_then(|entry| entry.detail.clone()),
        managed,
    }))
}

pub(super) async fn invalidate(
    state: &AppState,
    previous: &ManagedBmc,
    updated: &ManagedBmc,
    credentials_changed: bool,
) {
    if credentials_changed || !same_target(previous, updated) {
        let mut samples = state.monitoring.devices.lock().await;
        if let Some(sample) = samples.get_mut(&previous.identity)
            && previous.current_ip == updated.current_ip
            && previous.configuration_status != "draft"
        {
            sample.device = updated.clone();
            sample.power = None;
            sample.power_detail = None;
            sample.attempted_at = None;
            sample.detail = Some("登录凭据已更新，等待重新采集".into());
        } else {
            samples.remove(&previous.identity);
        }
    }
}

pub(super) async fn run(state: Arc<AppState>) {
    let mut tasks = JoinSet::<(ManagedBmc, Instant)>::new();
    let mut active = HashMap::<Ipv4Addr, String>::new();
    let mut scheduled = HashMap::<String, (ManagedBmc, Instant)>::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        while let Some(result) = tasks.try_join_next() {
            match result {
                Ok((device, started)) => {
                    active.remove(&device.current_ip);
                    scheduled.insert(device.identity.clone(), (device, started));
                }
                Err(error) => {
                    tracing::error!(%error, "monitoring worker stopped unexpectedly");
                    // Recover all tracked addresses after the remaining workers finish.
                    while let Some(result) = tasks.join_next().await {
                        if let Ok((device, started)) = result {
                            scheduled.insert(device.identity.clone(), (device, started));
                        }
                    }
                    active.clear();
                }
            }
        }
        let result = {
            let _edit = state.inventory_edit.lock().await;
            state
                .inventory
                .monitoring_interval()
                .and_then(|interval| state.inventory.list().map(|devices| (interval, devices)))
        };
        let (seconds, devices) = match result {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "could not read monitoring settings or inventory");
                continue;
            }
        };
        let identities: HashSet<_> = devices
            .iter()
            .map(|device| device.identity.as_str())
            .collect();
        scheduled.retain(|identity, _| identities.contains(identity.as_str()));
        state
            .monitoring
            .devices
            .lock()
            .await
            .retain(|identity, _| identities.contains(identity.as_str()));
        if seconds == 0 {
            continue;
        }
        let interval = Duration::from_secs(seconds);
        let mut due = devices
            .into_iter()
            .filter(|device| {
                device.configuration_status != "draft"
                    && (device.credential_username.is_some()
                        || !device.credential_profile.is_empty())
                    && scheduled
                        .get(&device.identity)
                        .is_none_or(|(previous, started)| {
                            !same_target(previous, device) || started.elapsed() >= interval
                        })
            })
            .collect::<Vec<_>>();
        // Schedule brand-new or changed targets first, then those waiting the longest.
        due.sort_by_key(|device| {
            scheduled
                .get(&device.identity)
                .filter(|(previous, _)| same_target(previous, device))
                .map(|(_, started)| *started)
        });
        for device in due {
            if tasks.len() >= MAX_IN_FLIGHT {
                break;
            }
            if active.contains_key(&device.current_ip)
                || active.values().any(|identity| identity == &device.identity)
            {
                continue;
            }
            active.insert(device.current_ip, device.identity.clone());
            let state = state.clone();
            tasks.spawn(async move {
                let started = Instant::now();
                collect(&state, &device).await;
                (device, started)
            });
        }
    }
}

struct Failure {
    online: &'static str,
    redfish: &'static str,
    auth: &'static str,
    detail: String,
}

impl Failure {
    fn offline() -> Self {
        Self {
            online: "offline",
            redfish: "unreachable",
            auth: "unknown",
            detail: "无法连接 BMC HTTPS".into(),
        }
    }

    fn redfish(detail: impl Into<String>) -> Self {
        Self {
            online: "online",
            redfish: "reachable",
            auth: "unknown",
            detail: detail.into(),
        }
    }

    fn from_read(error: RedfishError) -> Self {
        match error {
            RedfishError::ResourceAccess {
                status: StatusCode::UNAUTHORIZED,
                path,
            } => Self {
                auth: "failed",
                ..Self::redfish(format!("Redfish 需要重新认证（HTTP 401） · {path}"))
            },
            RedfishError::ResourceAccess {
                status: StatusCode::FORBIDDEN,
                path,
            } => Self {
                auth: "forbidden",
                ..Self::redfish(format!("当前账号无权读取（HTTP 403） · {path}"))
            },
            _ => Self::redfish(format!("Redfish 读取失败 · {error}")),
        }
    }
}

async fn read_client(
    state: &AppState,
    device: &ManagedBmc,
) -> Result<(RedfishClient, String), Failure> {
    let credentials = credentials_for_managed_bmc(state, device)
        .await
        .map_err(|error| Failure::redfish(error.message))?;
    let fingerprint = probe_certificate(device.current_ip)
        .await
        .map_err(|_| Failure::offline())?
        .sha256;
    if device
        .certificate_fingerprint
        .as_ref()
        .is_some_and(|expected| !fingerprint.eq_ignore_ascii_case(expected))
    {
        return Err(Failure::redfish("BMC HTTPS 证书指纹已变更"));
    }
    let client = RedfishClient::for_ipv4_with_fingerprint(
        device.current_ip,
        &credentials,
        Some(&fingerprint),
    )
    .map_err(Failure::from_read)?;
    Ok((client, fingerprint))
}

pub(super) async fn recheck_power(
    state: &AppState,
    identity: &str,
    expected_ip: Option<Ipv4Addr>,
) -> Result<ManagedPowerStatusResponse, ApiError> {
    let device = state
        .inventory
        .find(identity)
        .map_err(inventory_api_error)?
        .ok_or_else(|| ApiError::not_found("managed BMC was not found"))?;
    if device.configuration_status == "draft"
        || expected_ip.is_some_and(|ip| ip != device.current_ip)
    {
        return Err(ApiError::conflict("BMC 地址已变化，请重新确认操作目标"));
    }
    let (fingerprint, result) = match read_client(state, &device).await {
        Ok((client, fingerprint)) => (Some(fingerprint), read_power(&client).await),
        Err(error) => (None, Err(error)),
    };
    let power = result.as_ref().ok().cloned();
    let detail = result.as_ref().err().map(|error| error.detail.clone());
    if !publish_power(state, &device, fingerprint.as_deref(), result, false).await {
        return Err(ApiError::conflict("BMC 地址或登录凭据已变化"));
    }
    let managed = state
        .inventory
        .find(identity)
        .map_err(inventory_api_error)?
        .ok_or_else(|| ApiError::not_found("managed BMC was not found"))?;
    Ok(ManagedPowerStatusResponse {
        managed,
        power,
        detail,
        certificate_fingerprint: None,
        certificate_trust_required: false,
    })
}

async fn read_power(client: &RedfishClient) -> Result<PowerStatus, Failure> {
    match timeout(POWER_TIMEOUT, client.power_status()).await {
        Ok(result) => result.map_err(Failure::from_read),
        Err(_) => Err(Failure::redfish("读取服务器电源状态超时")),
    }
}

async fn collect(state: &AppState, device: &ManagedBmc) {
    let setup = read_client(state, device).await;
    let (client, fingerprint) = match setup {
        Ok(value) => value,
        Err(failure) => {
            publish_power(state, device, None, Err(failure), true).await;
            return;
        }
    };
    let power = read_power(&client).await;
    let access_rejected = power
        .as_ref()
        .is_err_and(|error| matches!(error.auth, "failed" | "forbidden"));
    if !publish_power(state, device, Some(&fingerprint), power, access_rejected).await
        || access_rejected
    {
        return;
    }
    let telemetry = match timeout(
        TELEMETRY_TIMEOUT,
        client.read_only_telemetry(device.hardware_model.as_deref()),
    )
    .await
    {
        Ok(result) => result.map_err(Failure::from_read),
        Err(_) => Err(Failure::redfish("硬件监控采集超时")),
    };
    publish_telemetry(state, device, telemetry).await;
}

async fn publish_power(
    state: &AppState,
    device: &ManagedBmc,
    fingerprint: Option<&str>,
    result: Result<PowerStatus, Failure>,
    telemetry_skipped: bool,
) -> bool {
    let _edit = state.inventory_edit.lock().await;
    let Ok(Some(current)) = state.inventory.find(&device.identity) else {
        return false;
    };
    if !same_target(device, &current) {
        return false;
    }
    if let Some(fingerprint) = fingerprint
        && current.certificate_fingerprint.is_none()
        && let Err(error) = state
            .inventory
            .set_certificate_fingerprint(&device.identity, fingerprint)
    {
        tracing::warn!(%error, identity = %device.identity, "could not persist monitoring certificate");
    }
    let (online, redfish, auth, detail) = match &result {
        Ok(_) => ("online", "reachable", "success", None),
        Err(error) => (
            error.online,
            error.redfish,
            error.auth,
            Some(error.detail.as_str()),
        ),
    };
    if let Err(error) =
        state
            .inventory
            .record_health(&device.identity, online, redfish, auth, detail)
    {
        tracing::warn!(%error, identity = %device.identity, "could not persist BMC connection status");
    }
    let mut samples = state.monitoring.devices.lock().await;
    let entry = samples
        .entry(device.identity.clone())
        .or_insert_with(|| DeviceSample::new(current.clone()));
    if !same_target(&entry.device, &current) {
        *entry = DeviceSample::new(current);
    }
    entry.power_detail = detail.map(str::to_owned);
    entry.power = result.ok();
    if telemetry_skipped {
        entry.attempted_at = Some(current_timestamp_seconds());
        entry.detail = entry.power_detail.clone();
    }
    true
}

async fn publish_telemetry(
    state: &AppState,
    device: &ManagedBmc,
    result: Result<TelemetrySnapshot, Failure>,
) {
    let _edit = state.inventory_edit.lock().await;
    let Ok(Some(current)) = state.inventory.find(&device.identity) else {
        return;
    };
    if !same_target(device, &current) {
        return;
    }
    let mut samples = state.monitoring.devices.lock().await;
    let Some(sample) = samples
        .get_mut(&device.identity)
        .filter(|entry| same_target(&entry.device, &current))
    else {
        return;
    };
    let now = current_timestamp_seconds();
    sample.attempted_at = Some(now);
    match result {
        Ok(mut snapshot) => {
            let serial = snapshot
                .serial_number
                .as_deref()
                .or(current.serial_number.as_deref());
            let hardware = serial
                .map(str::to_owned)
                .unwrap_or_else(|| current.current_ip.to_string());
            for gpu in &mut snapshot.gpu.cards {
                let key = format!("{hardware}|{}", gpu.ecc_device_key);
                match state.inventory.record_gpu_ecc(
                    &device.identity,
                    &key,
                    now,
                    gpu.correctable_ecc_errors,
                    gpu.uncorrectable_ecc_errors,
                ) {
                    Ok(history) => gpu.ecc_history = history,
                    Err(error) => {
                        tracing::warn!(%error, identity = %device.identity, "could not persist GPU ECC history")
                    }
                }
            }
            if let Err(error) = state.inventory.record_hardware_identity(
                &device.identity,
                device.current_ip,
                snapshot.bmc_mac.as_deref(),
                snapshot.serial_number.as_deref(),
                snapshot.model.as_deref(),
            ) {
                tracing::warn!(%error, identity = %device.identity, "could not persist BMC hardware identity");
            }
            if let Err(error) = state.inventory.record_telemetry(
                &device.identity,
                snapshot.power_watts,
                snapshot.temperature_celsius,
            ) {
                tracing::warn!(%error, identity = %device.identity, "could not persist BMC telemetry");
            }
            if sample.power.is_none() {
                let _ = state.inventory.record_health(
                    &device.identity,
                    "online",
                    "reachable",
                    "success",
                    None,
                );
            }
            sample.collected_at = Some(now);
            sample.telemetry = Some(snapshot);
            sample.detail = None;
        }
        Err(failure) => {
            if matches!(failure.auth, "failed" | "forbidden") {
                let _ = state.inventory.record_health(
                    &device.identity,
                    failure.online,
                    failure.redfish,
                    failure.auth,
                    Some(&failure.detail),
                );
                sample.power_detail = Some(failure.detail.clone());
                sample.power = None;
            }
            sample.detail = Some(failure.detail);
        }
    }
}
