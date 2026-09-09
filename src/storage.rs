use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{BmcCandidate, ProvisionResult, ProvisionStatus, StaticNetwork};

/// A non-sensitive, durable record of a BMC that was configured or checked by this application.
/// Credentials are deliberately absent: they are never written to this database.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedBmc {
    pub identity: String,
    pub mac: Option<String>,
    pub scope_id: u64,
    pub scope_name: String,
    pub source_ip: Ipv4Addr,
    pub current_ip: Ipv4Addr,
    pub target_network: StaticNetwork,
    pub certificate_fingerprint: Option<String>,
    pub configuration_status: String,
    pub online_status: String,
    pub redfish_status: String,
    pub authentication_status: String,
    pub last_checked_at: Option<i64>,
    pub last_configured_at: Option<i64>,
    pub last_error: Option<String>,
}

/// Repeatable, non-secret values for provisioning. Passwords belong in the operating system
/// credential vault and are intentionally not represented by this type or stored in SQLite.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionDefaults {
    pub lessor_url: String,
    pub scope_id: u64,
    pub username: String,
    pub target_prefix: u8,
    pub target_gateway: String,
}

impl Default for ProvisionDefaults {
    fn default() -> Self {
        Self {
            lessor_url: "http://127.0.0.1:8080".to_owned(),
            scope_id: 1,
            username: "admin".to_owned(),
            target_prefix: 24,
            target_gateway: String::new(),
        }
    }
}

pub struct InventoryStore {
    connection: Mutex<Connection>,
}

impl InventoryStore {
    pub fn open_default() -> Result<Self, StoreError> {
        let path = default_database_path()?;
        Self::open(&path)
    }

    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StoreError::Directory)?;
        }
        let connection = Connection::open(path).map_err(StoreError::Database)?;
        connection
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS managed_bmcs (
                    identity TEXT PRIMARY KEY,
                    mac TEXT,
                    scope_id INTEGER NOT NULL,
                    scope_name TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    current_ip TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    target_prefix INTEGER NOT NULL,
                    target_gateway TEXT NOT NULL,
                    certificate_fingerprint TEXT,
                    configuration_status TEXT NOT NULL,
                    online_status TEXT NOT NULL,
                    redfish_status TEXT NOT NULL,
                    authentication_status TEXT NOT NULL,
                    last_checked_at INTEGER,
                    last_configured_at INTEGER,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS application_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                );
                ",
            )
            .map_err(StoreError::Database)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn load_defaults(&self) -> Result<ProvisionDefaults, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let value: Option<String> = connection
            .query_row(
                "SELECT setting_value FROM application_settings WHERE setting_key = 'provision_defaults'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::Database)?;
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::SettingsDecode))
            .transpose()
            .map(|value| value.unwrap_or_default())
    }

    pub fn save_defaults(&self, defaults: &ProvisionDefaults) -> Result<(), StoreError> {
        let value = serde_json::to_string(defaults).map_err(StoreError::SettingsEncode)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO application_settings (setting_key, setting_value) VALUES ('provision_defaults', ?1)
                 ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value",
                [value],
            )
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ManagedBmc>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let mut statement = connection
            .prepare(
                "SELECT identity, mac, scope_id, scope_name, source_ip, current_ip, target_ip,
                        target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                        online_status, redfish_status, authentication_status, last_checked_at,
                        last_configured_at, last_error
                 FROM managed_bmcs ORDER BY COALESCE(last_configured_at, 0) DESC, current_ip",
            )
            .map_err(StoreError::Database)?;
        statement
            .query_map([], row_to_managed_bmc)
            .map_err(StoreError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::Database)
    }

    pub fn find(&self, identity: &str) -> Result<Option<ManagedBmc>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .query_row(
                "SELECT identity, mac, scope_id, scope_name, source_ip, current_ip, target_ip,
                        target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                        online_status, redfish_status, authentication_status, last_checked_at,
                        last_configured_at, last_error
                 FROM managed_bmcs WHERE identity = ?1",
                [identity],
                row_to_managed_bmc,
            )
            .optional()
            .map_err(StoreError::Database)
    }

    pub fn record_provision(
        &self,
        candidate: &BmcCandidate,
        network: &StaticNetwork,
        fingerprint: Option<&str>,
        result: Option<&ProvisionResult>,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        let identity = identity(candidate);
        let now = timestamp();
        let (current_ip, configuration_status, online, redfish, authentication) = match result {
            Some(result) if matches!(result.status, ProvisionStatus::Completed) => (
                result.target_ip,
                "completed",
                "online",
                "reachable",
                "success",
            ),
            Some(result) => (
                result.target_ip,
                "network_changed_unverified",
                "unknown",
                "unknown",
                "unknown",
            ),
            None => (candidate.ip, "failed", "unknown", "unknown", "unknown"),
        };
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO managed_bmcs (
                    identity, mac, scope_id, scope_name, source_ip, current_ip, target_ip,
                    target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                    online_status, redfish_status, authentication_status, last_checked_at,
                    last_configured_at, last_error
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                ON CONFLICT(identity) DO UPDATE SET
                    mac=excluded.mac, scope_id=excluded.scope_id, scope_name=excluded.scope_name,
                    source_ip=excluded.source_ip, current_ip=excluded.current_ip, target_ip=excluded.target_ip,
                    target_prefix=excluded.target_prefix, target_gateway=excluded.target_gateway,
                    certificate_fingerprint=excluded.certificate_fingerprint,
                    configuration_status=excluded.configuration_status, online_status=excluded.online_status,
                    redfish_status=excluded.redfish_status, authentication_status=excluded.authentication_status,
                    last_checked_at=excluded.last_checked_at, last_configured_at=excluded.last_configured_at,
                    last_error=excluded.last_error",
                params![
                    identity, candidate.mac, candidate.scope_id, candidate.scope_name,
                    candidate.ip.to_string(), current_ip.to_string(), network.address.to_string(),
                    i64::from(network.prefix), network.gateway.to_string(), fingerprint,
                    configuration_status, online, redfish, authentication, now, now, error,
                ],
            )
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub fn record_health(
        &self,
        identity: &str,
        online: &str,
        redfish: &str,
        authentication: &str,
        error: Option<&str>,
    ) -> Result<ManagedBmc, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "UPDATE managed_bmcs SET online_status=?2, redfish_status=?3,
                 authentication_status=?4, last_checked_at=?5, last_error=?6 WHERE identity=?1",
                params![
                    identity,
                    online,
                    redfish,
                    authentication,
                    timestamp(),
                    error
                ],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        self.find(identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Add a known BMC to the local inventory without contacting it or changing its network.
    /// This is useful for preserving an operator-maintained record that was not discovered by
    /// the local lessor instance.
    pub fn add_manual(
        &self,
        current_ip: Ipv4Addr,
        mac: Option<&str>,
        scope_name: Option<&str>,
    ) -> Result<ManagedBmc, StoreError> {
        let identity = mac
            .map(str::to_owned)
            .unwrap_or_else(|| format!("manual-{current_ip}"));
        let now = timestamp();
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO managed_bmcs (
                    identity, mac, scope_id, scope_name, source_ip, current_ip, target_ip,
                    target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                    online_status, redfish_status, authentication_status, last_checked_at,
                    last_configured_at, last_error
                ) VALUES (?1, ?2, 0, ?3, ?4, ?4, ?4, 24, '0.0.0.0', NULL, 'manual',
                          'unknown', 'unknown', 'unknown', NULL, ?5, NULL)
                ON CONFLICT(identity) DO UPDATE SET
                    mac=excluded.mac, scope_name=excluded.scope_name, current_ip=excluded.current_ip",
                params![identity, mac, scope_name.unwrap_or("手动添加"), current_ip.to_string(), now],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        self.find(&identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Changes only the local inventory address. It never sends a Redfish request.
    pub fn update_address(
        &self,
        identity: &str,
        current_ip: Ipv4Addr,
    ) -> Result<ManagedBmc, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET current_ip=?2, online_status='unknown',
                 redfish_status='unknown', authentication_status='unknown', last_checked_at=NULL
                 WHERE identity=?1",
                params![identity, current_ip.to_string()],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        self.find(identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Deletes one local inventory entry. The BMC itself is untouched.
    pub fn delete(&self, identity: &str) -> Result<(), StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute("DELETE FROM managed_bmcs WHERE identity=?1", [identity])
            .map_err(StoreError::Database)?;
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        Ok(())
    }
}

fn row_to_managed_bmc(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedBmc> {
    let parse_ip = |index| -> rusqlite::Result<Ipv4Addr> {
        row.get::<_, String>(index)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidQuery)
    };
    Ok(ManagedBmc {
        identity: row.get(0)?,
        mac: row.get(1)?,
        scope_id: row.get::<_, i64>(2)? as u64,
        scope_name: row.get(3)?,
        source_ip: parse_ip(4)?,
        current_ip: parse_ip(5)?,
        target_network: StaticNetwork {
            address: parse_ip(6)?,
            prefix: row.get::<_, i64>(7)? as u8,
            gateway: parse_ip(8)?,
        },
        certificate_fingerprint: row.get(9)?,
        configuration_status: row.get(10)?,
        online_status: row.get(11)?,
        redfish_status: row.get(12)?,
        authentication_status: row.get(13)?,
        last_checked_at: row.get(14)?,
        last_configured_at: row.get(15)?,
        last_error: row.get(16)?,
    })
}

fn identity(candidate: &BmcCandidate) -> String {
    candidate
        .mac
        .clone()
        .unwrap_or_else(|| format!("scope-{}-ip-{}", candidate.scope_id, candidate.ip))
}

fn default_database_path() -> Result<PathBuf, StoreError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .ok_or(StoreError::NoDataDirectory)?;
    Ok(base.join("bmc-provisioner").join("inventory.sqlite3"))
}

fn timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("could not create inventory directory")]
    Directory(#[source] std::io::Error),
    #[error("could not open inventory database")]
    Database(#[source] rusqlite::Error),
    #[error("inventory database lock was poisoned")]
    Lock,
    #[error("no local application-data directory is available")]
    NoDataDirectory,
    #[error("managed BMC record was not found")]
    MissingRecord,
    #[error("could not encode provisioning defaults")]
    SettingsEncode(#[source] serde_json::Error),
    #[error("stored provisioning defaults are invalid")]
    SettingsDecode(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn candidate() -> BmcCandidate {
        BmcCandidate {
            scope_id: 7,
            scope_name: "BMC management".to_owned(),
            subnet: Ipv4Addr::new(192, 168, 1, 0),
            prefix: 24,
            ip: Ipv4Addr::new(192, 168, 1, 101),
            mac: Some("00:11:22:33:44:55".to_owned()),
            first_seen: 1,
            last_seen: 2,
        }
    }

    #[test]
    fn retains_only_non_sensitive_provisioning_inventory() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let network = StaticNetwork {
            address: Ipv4Addr::new(10, 10, 20, 101),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 10, 20, 1),
        };
        let result = ProvisionResult {
            status: ProvisionStatus::Completed,
            source_ip: candidate().ip,
            target_ip: network.address,
            account_uri: "/redfish/v1/AccountService/Accounts/1".to_owned(),
            ethernet_interface_uri: "/redfish/v1/Managers/1/EthernetInterfaces/1".to_owned(),
        };

        store
            .record_provision(
                &candidate(),
                &network,
                Some("a certificate fingerprint"),
                Some(&result),
                None,
            )
            .unwrap();
        let managed = store.list().unwrap();

        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].identity, "00:11:22:33:44:55");
        assert_eq!(managed[0].current_ip, network.address);
        assert_eq!(managed[0].authentication_status, "success");
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn manually_added_bmc_can_be_updated_and_deleted_without_a_provisioning_record() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let created = store
            .add_manual(
                Ipv4Addr::new(172, 16, 40, 200),
                Some("00:11:22:33:44:55"),
                Some("机房 A"),
            )
            .unwrap();
        assert_eq!(created.configuration_status, "manual");

        let updated = store
            .update_address(&created.identity, Ipv4Addr::new(172, 16, 40, 201))
            .unwrap();
        assert_eq!(updated.current_ip, Ipv4Addr::new(172, 16, 40, 201));
        assert_eq!(updated.online_status, "unknown");

        store.delete(&created.identity).unwrap();
        assert!(store.list().unwrap().is_empty());
        drop(store);
        let _ = fs::remove_file(path);
    }
}
