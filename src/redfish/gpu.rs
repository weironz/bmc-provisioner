//! Optional accelerator inventory. Missing/denied resources never become zero readings.
use super::*;
use std::collections::HashSet;
use tokio::time::{Instant, timeout_at};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuTelemetry {
    pub discovery: String,
    pub available_count: Option<usize>,
    pub memory_capacity_mib: Option<f64>,
    pub cards: Vec<GpuCard>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuCard {
    pub id: String,
    pub model: Option<String>,
    pub state: Option<String>,
    pub health: Option<String>,
    pub memory_capacity_mib: Option<f64>,
    pub memory_utilization_percent: Option<f64>,
    pub memory_bandwidth_percent: Option<f64>,
    pub utilization_percent: Option<f64>,
    pub temperature_celsius: Option<f64>,
    pub power_watts: Option<f64>,
    pub power_limit_watts: Option<f64>,
    pub correctable_ecc_errors: Option<f64>,
    pub uncorrectable_ecc_errors: Option<f64>,
    pub correctable_row_remaps: Option<f64>,
    pub uncorrectable_row_remaps: Option<f64>,
    pub warnings: Vec<String>,
}

impl RedfishClient {
    // One budget for the entire optional pass, plus a short per-request timeout. Reads still
    // go through get_json, preserving origin validation and pinned TLS.
    async fn gpu_read(&self, uri: &str, deadline: Instant) -> Result<Value, &'static str> {
        match timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(4)),
            self.get_json(uri),
        )
        .await
        {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(RedfishError::AuthenticationFailed)) => Err("认证失败或无读取权限"),
            Ok(Err(RedfishError::UnexpectedStatus { status, .. }))
                if status == StatusCode::FORBIDDEN =>
            {
                Err("无读取权限")
            }
            Ok(Err(RedfishError::UnexpectedStatus { status, .. }))
                if status == StatusCode::NOT_FOUND =>
            {
                Err("接口未提供")
            }
            Err(_) => Err("读取超时"),
            _ => Err("读取失败"),
        }
    }

    pub(super) async fn gpu_telemetry(
        &self,
        systems: &Collection,
        host_uri: &str,
        host: &Value,
    ) -> GpuTelemetry {
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut cards = Vec::new();
        let mut warnings = Vec::new();
        let mut seen = HashSet::new();
        let mut complete = true;
        // HGX publishes the authoritative accelerator inventory. Host System_0 may expose
        // aliases of those same GPUs: never add both sets together (B300 otherwise counts 16).
        let hgx_system = systems
            .members
            .iter()
            .find(|system| system.odata_id.ends_with("/HGX_Baseboard_0"));
        let selected: Vec<_> = match hgx_system {
            Some(system) => vec![system],
            None => systems.members.iter().take(16).collect(),
        };
        let mut inventory = Vec::new();
        for system in selected {
            let resource = if system.odata_id == host_uri {
                host.clone()
            } else {
                match self.gpu_read(&system.odata_id, deadline).await {
                    Ok(value) => value,
                    Err(error) => {
                        warnings.push(format!("GPU 系统清单：{error}"));
                        complete = false;
                        continue;
                    }
                }
            };
            let hgx = system.odata_id.ends_with("/HGX_Baseboard_0");
            let fallback = format!("{}/Processors", system.odata_id);
            let Some(uri) =
                resource_link(&resource, "Processors").or(hgx.then_some(fallback.as_str()))
            else {
                complete = false;
                continue;
            };
            let mut next = Some(uri.to_owned());
            let mut pages = HashSet::new();
            while let Some(uri) = next.take() {
                if pages.len() >= 8 || !pages.insert(uri.clone()) || Instant::now() >= deadline {
                    complete = false;
                    break;
                }
                let expanded = format!("{uri}?$expand=*($levels=1)");
                let response = if hgx && !uri.contains('?') {
                    match self.gpu_read(&expanded, deadline).await {
                        Ok(value) => Ok(value),
                        Err(_) => self.gpu_read(&uri, deadline).await,
                    }
                } else {
                    self.gpu_read(&uri, deadline).await
                };
                let collection = match response {
                    Ok(value) => value,
                    Err(error) => {
                        warnings.push(format!("GPU 处理器清单：{error}"));
                        complete = false;
                        break;
                    }
                };
                let Some(members) = collection.get("Members").and_then(Value::as_array) else {
                    complete = false;
                    break;
                };
                if members.len() > 128 {
                    complete = false;
                }
                for member in members.iter().take(128) {
                    let member_uri = member
                        .get("@odata.id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !member_uri.is_empty() && !seen.insert(member_uri.to_owned()) {
                        continue;
                    }
                    let value = if member.get("ProcessorType").is_some() {
                        member.clone()
                    } else {
                        match self.gpu_read(member_uri, deadline).await {
                            Ok(value) => value,
                            Err(error) => {
                                warnings.push(format!("处理器资源：{error}"));
                                complete = false;
                                continue;
                            }
                        }
                    };
                    let kind = value.get("ProcessorType").and_then(Value::as_str);
                    let id = value
                        .get("Id")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| member_uri.rsplit('/').next().unwrap_or("GPU"));
                    if kind == Some("GPU") || (hgx && kind.is_none() && id.starts_with("GPU_")) {
                        inventory.push((member_uri.to_owned(), value, hgx));
                    } else if kind.is_none() {
                        complete = false;
                    }
                }
                next = collection
                    .get("Members@odata.nextLink")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
        if hgx_system.is_none() && systems.members.len() > 16 {
            complete = false;
        }
        // Finish inventory first so a slow metrics endpoint cannot hide the remaining cards.
        for (uri, value, hgx) in inventory {
            cards.push(self.gpu_card(&uri, &value, hgx, deadline).await);
        }
        if !complete {
            warnings.push("部分硬件清单未能读取，GPU 数量可能不完整。".into());
        }
        let available_count = cards
            .iter()
            .map(|card| {
                card.state
                    .as_deref()
                    .map(|state| usize::from(state == "Enabled"))
            })
            .sum();
        let memory_capacity_mib = if complete && !cards.is_empty() {
            cards.iter().map(|card| card.memory_capacity_mib).sum()
        } else {
            None
        };
        GpuTelemetry {
            discovery: if complete {
                if cards.is_empty() {
                    "absent"
                } else {
                    "available"
                }
            } else if cards.is_empty() {
                "unknown"
            } else {
                "partial"
            }
            .into(),
            available_count,
            memory_capacity_mib,
            cards,
            warnings,
        }
    }

    async fn gpu_card(&self, uri: &str, resource: &Value, hgx: bool, deadline: Instant) -> GpuCard {
        let mut card = GpuCard {
            id: string_field(resource, "Id")
                .unwrap_or_else(|| uri.rsplit('/').next().unwrap_or("GPU").into()),
            model: string_field(resource, "Model"),
            state: resource
                .pointer("/Status/State")
                .and_then(Value::as_str)
                .map(str::to_owned),
            health: resource
                .pointer("/Status/Health")
                .and_then(Value::as_str)
                .map(str::to_owned),
            memory_capacity_mib: metric(resource, "/MemorySummary/TotalMemorySizeMiB"),
            ..Default::default()
        };
        let env = metric_uri(
            resource,
            "EnvironmentMetrics",
            uri,
            "EnvironmentMetrics",
            hgx,
        );
        let proc = metric_uri(resource, "Metrics", uri, "ProcessorMetrics", hgx);
        let mem = resource
            .pointer("/MemorySummary/MemoryMetrics/@odata.id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| hgx.then(|| format!("{uri}/MemorySummary/MemoryMetrics")));
        let read = |uri: Option<String>| async move {
            match uri {
                Some(uri) => self.gpu_read(&uri, deadline).await.map(Some),
                None => Ok(None),
            }
        };
        // Some BMC firmware rejects overlapping authenticated metric reads. Keep this pass
        // serial and bounded, even though the HTTP pool can support concurrent requests.
        let environment = read(env).await;
        let processor = read(proc).await;
        let memory = read(mem).await;
        for (label, value) in [
            ("温度 / 功率", &environment),
            ("GPU 利用率", &processor),
            ("显存指标", &memory),
        ] {
            if let Err(error) = value {
                card.warnings.push(format!("{label}：{error}"));
            }
        }
        if let Ok(Some(value)) = environment {
            card.temperature_celsius = metric(&value, "/TemperatureCelsius/Reading");
            card.power_watts = metric(&value, "/PowerWatts/Reading");
            card.power_limit_watts = metric(&value, "/PowerLimitWatts/SetPoint");
        }
        if let Ok(Some(value)) = processor {
            // NVIDIA publishes this in its OEM metrics; generic BandwidthPercent is NOT GPU busy time.
            card.utilization_percent = percent(&value, "/Oem/Nvidia/SMUtilizationPercent");
        }
        if let Ok(Some(value)) = memory {
            apply_memory_metrics(&mut card, &value);
        }
        card
    }
}

fn metric_uri(resource: &Value, key: &str, uri: &str, suffix: &str, hgx: bool) -> Option<String> {
    resource_link(resource, key)
        .map(str::to_owned)
        .or_else(|| (hgx && !uri.is_empty()).then(|| format!("{uri}/{suffix}")))
}

fn metric(value: &Value, pointer: &str) -> Option<f64> {
    let value = value.pointer(pointer)?;
    value
        .as_f64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn percent(value: &Value, pointer: &str) -> Option<f64> {
    metric(value, pointer).filter(|value| *value <= 100.0)
}

fn apply_memory_metrics(card: &mut GpuCard, value: &Value) {
    card.memory_utilization_percent = percent(value, "/CapacityUtilizationPercent");
    card.memory_bandwidth_percent = percent(value, "/BandwidthPercent");
    card.correctable_ecc_errors = metric(value, "/LifeTime/CorrectableECCErrorCount");
    card.uncorrectable_ecc_errors = metric(value, "/LifeTime/UncorrectableECCErrorCount");
    card.correctable_row_remaps = metric(
        value,
        "/Oem/Nvidia/RowRemapping/CorrectableRowRemappingCount",
    );
    card.uncorrectable_row_remaps = metric(
        value,
        "/Oem/Nvidia/RowRemapping/UncorrectableRowRemappingCount",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[test]
    fn missing_and_zero_metrics_are_distinct_and_bandwidth_is_not_capacity() {
        let mut card = GpuCard::default();
        apply_memory_metrics(
            &mut card,
            &json!({"BandwidthPercent": 75, "CapacityUtilizationPercent": "0", "LifeTime":{"CorrectableECCErrorCount":0}}),
        );
        assert_eq!(card.memory_utilization_percent, Some(0.0));
        assert_eq!(card.memory_bandwidth_percent, Some(75.0));
        assert_eq!(card.correctable_ecc_errors, Some(0.0));
        assert_eq!(card.uncorrectable_ecc_errors, None);
        assert_eq!(metric(&json!({"a":"NaN"}), "/a"), None);
        assert_eq!(percent(&json!({"a":101}), "/a"), None);
    }

    async fn fixture(members: Value) -> (MockServer, RedfishClient, Collection, Value) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/processors"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Members":members})))
            .mount(&server)
            .await;
        let client = RedfishClient::new_for_mock(
            Url::parse(&server.uri()).unwrap(),
            &Credentials {
                username: "test".into(),
                current_password: "test".into(),
                new_password: "test".into(),
            },
        );
        let systems: Collection =
            serde_json::from_value(json!({"Members":[{"@odata.id":"/host"}]})).unwrap();
        (
            server,
            client,
            systems,
            json!({"Processors":{"@odata.id":"/processors"}}),
        )
    }

    #[tokio::test]
    async fn cpu_only_is_absent_but_failed_discovery_is_unknown() {
        let (_server, client, systems, host) =
            fixture(json!([{"Id":"CPU0","ProcessorType":"CPU"}])).await;
        assert_eq!(
            client
                .gpu_telemetry(&systems, "/host", &host)
                .await
                .discovery,
            "absent"
        );
        assert_eq!(
            client
                .gpu_telemetry(&systems, "/host", &json!({}))
                .await
                .discovery,
            "unknown"
        );
    }

    #[tokio::test]
    async fn sums_heterogeneous_cards_excludes_fpga_and_keeps_offline_state() {
        let (_server, client, systems, host) = fixture(json!([
            {"Id":"GPU0","ProcessorType":"GPU","MemorySummary":{"TotalMemorySizeMiB":8192},"Status":{"State":"Enabled"}},
            {"Id":"GPU1","ProcessorType":"GPU","MemorySummary":{"TotalMemorySizeMiB":16384},"Status":{"State":"Disabled"}},
            {"Id":"FPGA0","ProcessorType":"FPGA"}
        ])).await;
        let data = client.gpu_telemetry(&systems, "/host", &host).await;
        assert_eq!(data.cards.len(), 2);
        assert_eq!(data.available_count, Some(1));
        assert_eq!(data.memory_capacity_mib, Some(24576.0));
        assert_eq!(data.cards[0].power_watts, None);
    }

    #[tokio::test]
    async fn hgx_inventory_does_not_double_count_host_aliases() {
        let (server, client, _, _) = fixture(json!([])).await;
        let systems: Collection = serde_json::from_value(json!({"Members":[
            {"@odata.id":"/redfish/v1/Systems/HGX_Baseboard_0"}, {"@odata.id":"/host"}
        ]}))
        .unwrap();
        Mock::given(path("/redfish/v1/Systems/HGX_Baseboard_0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"Processors":{"@odata.id":"/hgx"}})),
            )
            .mount(&server)
            .await;
        Mock::given(path("/hgx")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"Members":[{"@odata.id":"/GPU_0","Id":"GPU_0","ProcessorType":"GPU","Status":{"State":"Enabled"},"MemorySummary":{"TotalMemorySizeMiB":275040}}]}))).mount(&server).await;
        Mock::given(path("/GPU_0/ProcessorMetrics"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"Oem":{"Nvidia":{"SMUtilizationPercent":0}}})),
            )
            .mount(&server)
            .await;
        Mock::given(path("/host"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let data = client.gpu_telemetry(&systems, "/host", &json!({})).await;
        assert_eq!(data.discovery, "available");
        assert_eq!(data.cards.len(), 1);
        assert_eq!(data.memory_capacity_mib, Some(275040.0));
        assert_eq!(data.cards[0].utilization_percent, Some(0.0));
    }

    #[tokio::test]
    async fn denied_metrics_preserve_inventory_and_report_failure() {
        let (server, client, systems, host) = fixture(json!([{"Id":"GPU0","ProcessorType":"GPU","EnvironmentMetrics":{"@odata.id":"/denied"},"MemorySummary":{"MemoryMetrics":{"@odata.id":"/memory"}}}])).await;
        Mock::given(path("/denied"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(path("/memory"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"CapacityUtilizationPercent":0})),
            )
            .mount(&server)
            .await;
        let data = client.gpu_telemetry(&systems, "/host", &host).await;
        assert_eq!(data.cards.len(), 1);
        assert!(data.cards[0].warnings[0].contains("无读取权限"));
        assert_eq!(data.cards[0].memory_utilization_percent, Some(0.0));
        assert_eq!(data.cards[0].power_watts, None);
    }
}
