use super::*;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, Weak};

fn text(value: &Value, key: &str) -> Option<String> {
    let value = value.get(key)?.as_str()?.trim();
    if value.is_empty()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "na" | "n/a" | "unknown" | "not specified"
        )
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn product_identity(fru: &Value) -> (Option<String>, Option<String>) {
    let product = fru
        .get("Product")
        .or_else(|| fru.get("product"))
        .unwrap_or(&Value::Null);
    (
        text(product, "ProductName").or_else(|| text(product, "product_name")),
        text(product, "SerialNumber").or_else(|| text(product, "serial_number")),
    )
}

fn management_mac(ports: &[Value], address: &str) -> Option<String> {
    ports
        .iter()
        .filter(|port| {
            port.get("IPv4Addresses")
                .and_then(Value::as_array)
                .is_some_and(|addresses| {
                    addresses
                        .iter()
                        .any(|entry| entry.get("Address").and_then(Value::as_str) == Some(address))
                })
        })
        .find_map(|port| {
            text(port, "MACAddress").filter(|mac| {
                let parts: Vec<_> = mac.split(':').collect();
                parts.len() == 6
                    && parts
                        .iter()
                        .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
                    && mac != "00:00:00:00:00:00"
                    && !mac.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff")
            })
        })
        .map(|mac| mac.to_ascii_lowercase())
}

impl RedfishClient {
    /// Serialize reads to each BMC across polling clients, while allowing different BMCs
    /// to be collected concurrently. Weak entries do not retain disconnected controllers.
    pub(super) fn read_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        type Locks = Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>;
        static LOCKS: OnceLock<Locks> = OnceLock::new();
        let mut locks = LOCKS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        let origin = self.base_url.origin().ascii_serialization();
        if let Some(lock) = locks.get(&origin).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(origin, Arc::downgrade(&lock));
        lock
    }

    pub(super) async fn hardware_identity(
        &self,
        system: &Value,
        model_hint: Option<&str>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let mut model = text(system, "Model").or_else(|| {
            model_hint
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
        });
        let mut serial = text(system, "SerialNumber");
        if model.is_none()
            && let Some(uri) = resource_link(system, "FruInfo")
            && let Some(fru) = self.optional_value(uri).await
        {
            let (fru_model, fru_serial) = product_identity(&fru);
            model = fru_model;
            serial = serial.or(fru_serial);
        }
        // This is an AMI web API fallback, NOT a standard Redfish resource. Never use it
        // on arbitrary vendors or invoke the existing first-login password-change flow.
        if model.is_none()
            && text(system, "Manufacturer").is_some_and(|m| m.eq_ignore_ascii_case("ASRockRack"))
            && let Some(fru) = self.ami_fru().await
        {
            let (fru_model, fru_serial) = product_identity(&fru);
            model = fru_model;
            serial = serial.or(fru_serial);
        }
        let mut managers: Vec<String> = system
            .pointer("/Links/ManagedBy")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|m| {
                m.get("@odata.id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        if managers.is_empty()
            && let Some(root) = self.optional_value("/redfish/v1/").await
            && let Some(uri) = resource_link(&root, "Managers")
            && let Ok(collection) = self.get_json::<Collection>(uri).await
        {
            managers = collection.members.into_iter().map(|m| m.odata_id).collect();
        }
        let mut mac = None;
        for manager in managers.iter().take(4) {
            let Some(manager) = self.optional_value(manager).await else {
                continue;
            };
            let Some(uri) = resource_link(&manager, "EthernetInterfaces") else {
                continue;
            };
            let mut ports = self.expanded_collection_values(Some(uri)).await;
            // Some firmware ignores or rejects expansion. Follow the standard members then.
            if !ports.iter().any(|port| port.get("IPv4Addresses").is_some()) {
                ports = self.collection_values(Some(uri)).await;
            }
            mac = management_mac(&ports, self.base_url.host_str().unwrap_or_default());
            if mac.is_some() {
                break;
            }
        }
        (model, serial, mac)
    }

    async fn ami_fru(&self) -> Option<Value> {
        let lock = self.read_lock();
        let _guard = lock.lock().await;
        let script = self
            .client
            .get(self.resource_url("/source.min.js").ok()?)
            .send()
            .await
            .ok()?;
        if !script.status().is_success() {
            return None;
        }
        let script = script.text().await.ok()?;
        if !script.contains("/api/fru") || !script.contains("/api/session") {
            return None;
        }
        let session_url = self.resource_url("/api/session").ok()?;
        let response = self
            .client
            .post(session_url.clone())
            .form(&[("username", &self.username), ("password", &self.password)])
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let cookie = response_cookie(&response)?;
        let login = response.json::<Value>().await.ok();
        let csrf = login
            .as_ref()
            .and_then(|v| v.get("CSRFToken"))
            .and_then(Value::as_str);
        let mut result = None;
        if let Some(csrf) = csrf {
            if let Ok(url) = self.resource_url("/api/fru")
                && let Ok(response) = self
                    .client
                    .get(url)
                    .header(COOKIE, &cookie)
                    .header("X-CSRFTOKEN", csrf)
                    .send()
                    .await
                && response.status().is_success()
                && let Ok(frus) = response.json::<Vec<Value>>().await
            {
                result = frus.into_iter().find(|fru| {
                    fru.pointer("/device/name").and_then(Value::as_str) == Some("BMC_FRU")
                });
            }
        }
        // End only the temporary session created above, including on failed FRU reads.
        let mut logout = self.client.delete(session_url).header(COOKIE, cookie);
        if let Some(csrf) = csrf {
            logout = logout.header("X-CSRFTOKEN", csrf);
        }
        let _ = logout.send().await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn ami_fru_fallback_logs_out_and_cached_model_avoids_login() {
        let server = MockServer::start().await;
        let credentials = Credentials {
            username: "admin".into(),
            current_password: "test-only".into(),
            new_password: String::new(),
        };
        let client = RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials);
        Mock::given(method("GET"))
            .and(path("/source.min.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string("/api/session /api/fru"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/session"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Set-Cookie", "SID=test-session; Path=/; HttpOnly")
                    .set_body_json(json!({"CSRFToken":"test-token"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/api/fru")).and(header("X-CSRFTOKEN","test-token")).and(header("Cookie","SID=test-session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"device":{"name":"BMC_FRU"},"product":{"product_name":"8U16X-GNR2 B300","serial_number":"product-sn"},"board":{"product_name":"wrong-board"}}])))
            .expect(1).mount(&server).await;
        Mock::given(method("DELETE"))
            .and(path("/api/session"))
            .and(header("Cookie", "SID=test-session"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let system = json!({"Manufacturer":"ASRockRack","Model":" ","SerialNumber":"product-sn"});
        let (model, sn, _) = client.hardware_identity(&system, None).await;
        assert_eq!(model.as_deref(), Some("8U16X-GNR2 B300"));
        assert_eq!(sn.as_deref(), Some("product-sn"));
        assert_eq!(
            client.hardware_identity(&system, model.as_deref()).await.0,
            model
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn ami_fru_failure_still_logs_out() {
        let server = MockServer::start().await;
        let credentials = Credentials {
            username: "admin".into(),
            current_password: "test-only".into(),
            new_password: String::new(),
        };
        let client = RedfishClient::new_for_mock(Url::parse(&server.uri()).unwrap(), &credentials);
        Mock::given(method("GET"))
            .and(path("/source.min.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string("/api/session /api/fru"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/session"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Set-Cookie", "SID=test; Path=/")
                    .set_body_json(json!({"CSRFToken":"test"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fru"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/session"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        assert!(client.ami_fru().await.is_none());
        server.verify().await;
    }
    #[test]
    fn product_not_board_or_chassis_identity() {
        let fru = json!({"product":{"product_name":"8U16X-GNR2 B300","serial_number":"product-sn"}, "board":{"product_name":"board","serial_number":"board-sn"}});
        assert_eq!(
            product_identity(&fru),
            (Some("8U16X-GNR2 B300".into()), Some("product-sn".into()))
        );
        assert_eq!(
            product_identity(&json!({"Product":{"Info":"Product FRU Information"}})),
            (None, None)
        );
        assert_eq!(text(&json!({"Model":"  "}), "Model"), None);
    }
    #[test]
    fn mac_matches_bmc_address_not_usb_or_host() {
        let ports = vec![
            json!({"MACAddress":"AA:BB:CC:DD:EE:01","IPv4Addresses":[{"Address":"169.254.0.17"}]}),
            json!({"MACAddress":"9C:6B:00:E2:AF:06","IPv4Addresses":[{"Address":"172.16.40.10"}]}),
        ];
        assert_eq!(
            management_mac(&ports, "172.16.40.10"),
            Some("9c:6b:00:e2:af:06".into())
        );
        assert_eq!(management_mac(&ports, "172.16.40.11"), None);
    }
    #[test]
    fn current_power_uses_current_not_limits_or_average() {
        assert_eq!(
            current_chassis_power(
                &json!({"PowerControl":[{"PowerConsumedWatts":null,"PowerMetrics":{"CurConsumedWatts":4920,"AverageConsumedWatts":4925}}]})
            ),
            Some(4920.0)
        );
        assert_eq!(
            current_chassis_power(
                &json!({"PowerControl":[{"PowerConsumedWatts":0,"PowerMetrics":{"CurConsumedWatts":4920}}]})
            ),
            Some(0.0)
        );
        assert_eq!(
            current_chassis_power(
                &json!({"PowerControl":[{"PowerMetrics":{"AverageConsumedWatts":4925},"PowerLimit":{"LimitInWatts":500}}],"PowerWatts":{"Reading":2300}})
            ),
            None
        );
    }
}
