use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{BmcCandidate, ProvisionResult, ProvisionStatus, StaticNetwork};

/// A durable record of a BMC that was configured or checked by this application. Passwords are
/// stored separately as AES-256-GCM ciphertext; this response intentionally exposes only the
/// username and credential metadata needed by the user interface.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedBmc {
    pub identity: String,
    pub display_name: String,
    pub cluster_id: Option<i64>,
    pub mac: Option<String>,
    pub bmc_mac: Option<String>,
    pub serial_number: Option<String>,
    pub hardware_model: Option<String>,
    pub scope_id: u64,
    pub scope_name: String,
    /// Retained only to resolve legacy initialization profiles during the migration period.
    pub credential_profile: String,
    pub credential_username: Option<String>,
    pub credential_updated_at: Option<i64>,
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

/// A 256-bit application key kept outside SQLite. On the desktop it is protected by the OS
/// credential vault; containers must receive it through a mounted secret or environment.
#[derive(Clone)]
pub struct DeviceCredentialKey([u8; 32]);

impl DeviceCredentialKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Never serializable, debuggable, or returned through an HTTP response.
pub struct DeviceCredential {
    pub username: String,
    pub password: String,
}

/// An operator-defined group of servers. It is intentionally local metadata and never changes
/// a BMC, lessor scope, or DHCP lease.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BmcCluster {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
}

/// A compact, non-sensitive point collected from a BMC's Redfish telemetry. The local
/// history intentionally contains only measurements and a collection timestamp.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryHistoryPoint {
    pub collected_at: i64,
    pub power_watts: Option<f64>,
    pub temperature_celsius: Option<f64>,
}

/// Selects the retained telemetry precision used to answer a dashboard query.
#[derive(Clone, Copy, Debug)]
pub enum TelemetryHistoryResolution {
    Raw,
    FiveMinutes,
    OneHour,
}

/// Only a profile label and user name live in SQLite. Password material remains in the OS vault.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProfileMeta {
    pub name: String,
    pub username: String,
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
    #[serde(default = "default_batch_concurrency")]
    pub batch_concurrency: u8,
}

fn default_batch_concurrency() -> u8 {
    4
}

impl Default for ProvisionDefaults {
    fn default() -> Self {
        Self {
            lessor_url: "http://127.0.0.1:8080".to_owned(),
            scope_id: 1,
            username: "admin".to_owned(),
            target_prefix: 24,
            target_gateway: String::new(),
            batch_concurrency: default_batch_concurrency(),
        }
    }
}

pub struct InventoryStore {
    connection: Mutex<Connection>,
}

impl InventoryStore {
    pub fn open_default() -> Result<Self, StoreError> {
        let base = local_application_data_directory()?;
        let path = database_path(&base);
        migrate_legacy_database(&base, &path)?;
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
                    display_name TEXT NOT NULL DEFAULT '',
                    cluster_id INTEGER,
                    mac TEXT,
                    scope_id INTEGER NOT NULL,
                    scope_name TEXT NOT NULL,
                    credential_profile TEXT NOT NULL DEFAULT 'default',
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
                CREATE TABLE IF NOT EXISTS bmc_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS application_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS bmc_telemetry_history (
                    identity TEXT NOT NULL,
                    collected_at INTEGER NOT NULL,
                    power_watts REAL,
                    temperature_celsius REAL,
                    PRIMARY KEY (identity, collected_at)
                );
                CREATE INDEX IF NOT EXISTS idx_bmc_telemetry_history_identity_time
                    ON bmc_telemetry_history (identity, collected_at);
                CREATE TABLE IF NOT EXISTS bmc_telemetry_rollups (
                    identity TEXT NOT NULL,
                    resolution_seconds INTEGER NOT NULL,
                    window_start INTEGER NOT NULL,
                    power_watts REAL,
                    power_samples INTEGER NOT NULL,
                    temperature_celsius REAL,
                    temperature_samples INTEGER NOT NULL,
                    PRIMARY KEY (identity, resolution_seconds, window_start)
                );
                CREATE INDEX IF NOT EXISTS idx_bmc_telemetry_rollups_identity_time
                    ON bmc_telemetry_rollups (identity, resolution_seconds, window_start);
                CREATE TABLE IF NOT EXISTS bmc_device_credentials (
                    identity TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    secret_nonce BLOB NOT NULL,
                    secret_ciphertext BLOB NOT NULL,
                    key_version INTEGER NOT NULL DEFAULT 1,
                    updated_at INTEGER NOT NULL
                );
                ",
            )
            .map_err(StoreError::Database)?;
        ensure_managed_bmc_column(
            &connection,
            "credential_profile",
            "TEXT NOT NULL DEFAULT 'default'",
        )?;
        ensure_managed_bmc_column(&connection, "display_name", "TEXT NOT NULL DEFAULT ''")?;
        ensure_managed_bmc_column(&connection, "cluster_id", "INTEGER")?;
        ensure_managed_bmc_column(&connection, "bmc_mac", "TEXT")?;
        ensure_managed_bmc_column(&connection, "serial_number", "TEXT")?;
        ensure_managed_bmc_column(&connection, "hardware_model", "TEXT")?;
        backfill_telemetry_rollups(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn load_defaults(&self) -> Result<ProvisionDefaults, StoreError> {
        self.load_setting("provision_defaults")
            .map(|value| value.unwrap_or_default())
    }

    pub fn save_defaults(&self, defaults: &ProvisionDefaults) -> Result<(), StoreError> {
        self.save_setting("provision_defaults", defaults)
    }

    fn load_setting<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let value: Option<String> = connection
            .query_row(
                "SELECT setting_value FROM application_settings WHERE setting_key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::Database)?;
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::SettingsDecode))
            .transpose()
    }

    fn save_setting<T: Serialize + ?Sized>(&self, key: &str, value: &T) -> Result<(), StoreError> {
        let value = serde_json::to_string(value).map_err(StoreError::SettingsEncode)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO application_settings (setting_key, setting_value) VALUES (?1, ?2)
                 ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value",
                params![key, value],
            )
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub fn credential_profiles(&self) -> Result<Vec<CredentialProfileMeta>, StoreError> {
        self.load_setting("credential_profiles")
            .map(|profiles| profiles.unwrap_or_default())
    }

    pub fn save_credential_profiles(
        &self,
        profiles: &[CredentialProfileMeta],
    ) -> Result<(), StoreError> {
        self.save_setting("credential_profiles", profiles)
    }

    pub fn list_clusters(&self) -> Result<Vec<BmcCluster>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let mut statement = connection
            .prepare("SELECT id, name, created_at FROM bmc_clusters ORDER BY name COLLATE NOCASE")
            .map_err(StoreError::Database)?;
        statement
            .query_map([], row_to_cluster)
            .map_err(StoreError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::Database)
    }

    pub fn create_cluster(&self, name: &str) -> Result<BmcCluster, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO bmc_clusters (name, created_at) VALUES (?1, ?2)",
                params![name, timestamp()],
            )
            .map_err(StoreError::Database)?;
        let id = connection.last_insert_rowid();
        drop(connection);
        self.find_cluster(id)?.ok_or(StoreError::MissingRecord)
    }

    pub fn update_cluster(&self, id: i64, name: &str) -> Result<BmcCluster, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE bmc_clusters SET name=?2 WHERE id=?1",
                params![id, name],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        self.find_cluster(id)?.ok_or(StoreError::MissingRecord)
    }

    /// Deleting a cluster preserves every BMC history row and only removes its grouping.
    pub fn delete_cluster(&self, id: i64) -> Result<(), StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(StoreError::Database)?;
        transaction
            .execute(
                "UPDATE managed_bmcs SET cluster_id=NULL WHERE cluster_id=?1",
                [id],
            )
            .map_err(StoreError::Database)?;
        let changed = transaction
            .execute("DELETE FROM bmc_clusters WHERE id=?1", [id])
            .map_err(StoreError::Database)?;
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        transaction.commit().map_err(StoreError::Database)
    }

    pub fn set_cluster(
        &self,
        identity: &str,
        cluster_id: Option<i64>,
    ) -> Result<ManagedBmc, StoreError> {
        if let Some(cluster_id) = cluster_id
            && self.find_cluster(cluster_id)?.is_none()
        {
            return Err(StoreError::MissingRecord);
        }
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET cluster_id=?2 WHERE identity=?1",
                params![identity, cluster_id],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        self.find(identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Applies a local cluster association to every requested BMC atomically.  No BMC request
    /// is made; the transaction either updates the entire selection or none of it.
    pub fn set_cluster_many(
        &self,
        identities: &[String],
        cluster_id: i64,
    ) -> Result<(), StoreError> {
        if self.find_cluster(cluster_id)?.is_none() {
            return Err(StoreError::MissingRecord);
        }
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(StoreError::Database)?;
        for identity in identities {
            let changed = transaction
                .execute(
                    "UPDATE managed_bmcs SET cluster_id=?2 WHERE identity=?1",
                    params![identity, cluster_id],
                )
                .map_err(StoreError::Database)?;
            if changed == 0 {
                return Err(StoreError::MissingRecord);
            }
        }
        transaction.commit().map_err(StoreError::Database)
    }

    fn find_cluster(&self, id: i64) -> Result<Option<BmcCluster>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .query_row(
                "SELECT id, name, created_at FROM bmc_clusters WHERE id=?1",
                [id],
                row_to_cluster,
            )
            .optional()
            .map_err(StoreError::Database)
    }

    pub fn list(&self) -> Result<Vec<ManagedBmc>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let mut statement = connection
            .prepare(
                "SELECT b.identity, b.display_name, b.cluster_id, b.mac, b.scope_id, b.scope_name,
                        b.credential_profile, d.username, d.updated_at, b.source_ip, b.current_ip,
                        b.target_ip, b.target_prefix, b.target_gateway, b.certificate_fingerprint,
                        b.configuration_status, b.online_status, b.redfish_status, b.authentication_status,
                        b.last_checked_at, b.last_configured_at, b.last_error, b.bmc_mac, b.serial_number, b.hardware_model
                 FROM managed_bmcs b
                 LEFT JOIN bmc_device_credentials d ON d.identity = b.identity
                 ORDER BY COALESCE(b.last_configured_at, 0) DESC, b.current_ip",
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
                "SELECT b.identity, b.display_name, b.cluster_id, b.mac, b.scope_id, b.scope_name,
                        b.credential_profile, d.username, d.updated_at, b.source_ip, b.current_ip,
                        b.target_ip, b.target_prefix, b.target_gateway, b.certificate_fingerprint,
                        b.configuration_status, b.online_status, b.redfish_status, b.authentication_status,
                        b.last_checked_at, b.last_configured_at, b.last_error, b.bmc_mac, b.serial_number, b.hardware_model
                 FROM managed_bmcs b
                 LEFT JOIN bmc_device_credentials d ON d.identity = b.identity
                 WHERE b.identity = ?1",
                [identity],
                row_to_managed_bmc,
            )
            .optional()
            .map_err(StoreError::Database)
    }

    /// Preserve the last successful identity on partial scrapes. Late responses from an old
    /// address must not overwrite the identity of an edited device.
    pub fn record_hardware_identity(
        &self,
        identity: &str,
        address: Ipv4Addr,
        mac: Option<&str>,
        serial: Option<&str>,
        model: Option<&str>,
    ) -> Result<(), StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "UPDATE managed_bmcs SET
            bmc_mac=COALESCE(NULLIF(trim(?3),''),bmc_mac),
            serial_number=COALESCE(NULLIF(trim(?4),''),serial_number),
            hardware_model=COALESCE(NULLIF(trim(?5),''),hardware_model)
            WHERE identity=?1 AND current_ip=?2",
                params![identity, address.to_string(), mac, serial, model],
            )
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub fn record_provision(
        &self,
        candidate: &BmcCandidate,
        network: &StaticNetwork,
        fingerprint: Option<&str>,
        credential_profile: &str,
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
                    identity, mac, scope_id, scope_name, credential_profile, source_ip, current_ip, target_ip,
                    target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                    online_status, redfish_status, authentication_status, last_checked_at,
                    last_configured_at, last_error
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                ON CONFLICT(identity) DO UPDATE SET
                    mac=excluded.mac, scope_id=excluded.scope_id, scope_name=excluded.scope_name, credential_profile=excluded.credential_profile,
                    source_ip=excluded.source_ip, current_ip=excluded.current_ip, target_ip=excluded.target_ip,
                    target_prefix=excluded.target_prefix, target_gateway=excluded.target_gateway,
                    certificate_fingerprint=excluded.certificate_fingerprint,
                    configuration_status=excluded.configuration_status, online_status=excluded.online_status,
                    redfish_status=excluded.redfish_status, authentication_status=excluded.authentication_status,
                    last_checked_at=excluded.last_checked_at, last_configured_at=excluded.last_configured_at,
                    last_error=excluded.last_error",
                params![
                    identity, candidate.mac, candidate.scope_id, candidate.scope_name, credential_profile,
                    candidate.ip.to_string(), current_ip.to_string(), network.address.to_string(),
                    i64::from(network.prefix), network.gateway.to_string(), fingerprint,
                    configuration_status, online, redfish, authentication, now, now, error,
                ],
            )
            .map_err(StoreError::Database)?;
        Ok(())
    }

    /// Adopt an already-static controller after an authenticated, read-only Redfish check.
    /// This is local bookkeeping only: it never sends a PATCH to the BMC.
    pub fn record_adopted_static(
        &self,
        candidate: &BmcCandidate,
        network: &StaticNetwork,
        fingerprint: Option<&str>,
        credential_profile: &str,
    ) -> Result<ManagedBmc, StoreError> {
        let identity = identity(candidate);
        let now = timestamp();
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection.execute(
            "INSERT INTO managed_bmcs (
                identity, mac, scope_id, scope_name, credential_profile, source_ip, current_ip, target_ip,
                target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                online_status, redfish_status, authentication_status, last_checked_at,
                last_configured_at, last_error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6, ?7, ?8, ?9, 'adopted_static',
                      'online', 'reachable', 'success', ?10, ?10, NULL)
            ON CONFLICT(identity) DO UPDATE SET
                mac=excluded.mac, scope_id=excluded.scope_id, scope_name=excluded.scope_name,
                credential_profile=excluded.credential_profile, source_ip=excluded.source_ip,
                current_ip=excluded.current_ip, target_ip=excluded.target_ip,
                target_prefix=excluded.target_prefix, target_gateway=excluded.target_gateway,
                certificate_fingerprint=excluded.certificate_fingerprint,
                configuration_status='adopted_static', online_status='online',
                redfish_status='reachable', authentication_status='success',
                last_checked_at=excluded.last_checked_at, last_configured_at=excluded.last_configured_at,
                last_error=NULL",
            params![
                identity, candidate.mac, candidate.scope_id, candidate.scope_name, credential_profile,
                candidate.ip.to_string(), i64::from(network.prefix), network.gateway.to_string(), fingerprint, now,
            ],
        ).map_err(StoreError::Database)?;
        drop(connection);
        self.find(&identity)?.ok_or(StoreError::MissingRecord)
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

    /// Persists a successful Redfish sample for the dashboard. Raw samples support short-term
    /// troubleshooting, while local rollups retain longer operational trends at lower cost.
    pub fn record_telemetry(
        &self,
        identity: &str,
        power_watts: Option<f64>,
        temperature_celsius: Option<f64>,
    ) -> Result<(), StoreError> {
        if power_watts.is_none() && temperature_celsius.is_none() {
            return Ok(());
        }
        const RAW_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
        const FIVE_MINUTE_RETENTION_SECONDS: i64 = 90 * 24 * 60 * 60;
        const HOURLY_RETENTION_SECONDS: i64 = 365 * 24 * 60 * 60;
        let collected_at = timestamp();
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO bmc_telemetry_history (identity, collected_at, power_watts, temperature_celsius)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(identity, collected_at) DO UPDATE SET
                    power_watts=excluded.power_watts,
                    temperature_celsius=excluded.temperature_celsius",
                params![identity, collected_at, power_watts, temperature_celsius],
            )
            .map_err(StoreError::Database)?;
        upsert_telemetry_rollup(&connection, identity, collected_at, 5 * 60)?;
        upsert_telemetry_rollup(&connection, identity, collected_at, 60 * 60)?;
        connection
            .execute(
                "DELETE FROM bmc_telemetry_history WHERE collected_at < ?1",
                [collected_at - RAW_RETENTION_SECONDS],
            )
            .map_err(StoreError::Database)?;
        connection
            .execute(
                "DELETE FROM bmc_telemetry_rollups
                 WHERE resolution_seconds = ?1 AND window_start < ?2",
                params![5 * 60, collected_at - FIVE_MINUTE_RETENTION_SECONDS],
            )
            .map_err(StoreError::Database)?;
        connection
            .execute(
                "DELETE FROM bmc_telemetry_rollups
                 WHERE resolution_seconds = ?1 AND window_start < ?2",
                params![60 * 60, collected_at - HOURLY_RETENTION_SECONDS],
            )
            .map_err(StoreError::Database)?;
        Ok(())
    }

    /// Returns locally retained telemetry at an appropriate source precision. SQLite performs
    /// the final averaging so long dashboard ranges remain responsive.
    pub fn telemetry_history(
        &self,
        identity: &str,
        since: i64,
        bucket_seconds: i64,
        resolution: TelemetryHistoryResolution,
    ) -> Result<Vec<TelemetryHistoryPoint>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let (query, parameters): (&str, Vec<rusqlite::types::Value>) = match resolution {
            TelemetryHistoryResolution::Raw => (
                "SELECT (collected_at / ?3) * ?3, AVG(power_watts), AVG(temperature_celsius)
                 FROM bmc_telemetry_history
                 WHERE identity = ?1 AND collected_at >= ?2
                 GROUP BY (collected_at / ?3) * ?3
                 ORDER BY (collected_at / ?3) * ?3 ASC",
                vec![
                    identity.to_owned().into(),
                    since.into(),
                    bucket_seconds.into(),
                ],
            ),
            TelemetryHistoryResolution::FiveMinutes | TelemetryHistoryResolution::OneHour => {
                let source_resolution: i64 = match resolution {
                    TelemetryHistoryResolution::FiveMinutes => 5 * 60,
                    TelemetryHistoryResolution::OneHour => 60 * 60,
                    TelemetryHistoryResolution::Raw => unreachable!(),
                };
                (
                    "SELECT (window_start / ?4) * ?4,
                     SUM(power_watts * power_samples) / NULLIF(SUM(power_samples), 0),
                     SUM(temperature_celsius * temperature_samples) / NULLIF(SUM(temperature_samples), 0)
                     FROM bmc_telemetry_rollups
                     WHERE identity = ?1 AND window_start + resolution_seconds > ?2 AND resolution_seconds = ?3
                     GROUP BY (window_start / ?4) * ?4
                     ORDER BY (window_start / ?4) * ?4 ASC",
                    vec![identity.to_owned().into(), since.into(), source_resolution.into(), bucket_seconds.into()],
                )
            }
        };
        let mut statement = connection.prepare(query).map_err(StoreError::Database)?;
        let points = statement
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                Ok(TelemetryHistoryPoint {
                    collected_at: row.get(0)?,
                    power_watts: row.get(1)?,
                    temperature_celsius: row.get(2)?,
                })
            })
            .map_err(StoreError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;
        Ok(points)
    }

    /// Writes one BMC's credentials as authenticated ciphertext. The plaintext password exists
    /// only for the duration of this call and is never written to application settings or logs.
    /// Saving a device credential detaches the BMC from its legacy shared profile.
    pub fn save_device_credential(
        &self,
        identity: &str,
        username: &str,
        password: &str,
        key: &DeviceCredentialKey,
    ) -> Result<ManagedBmc, StoreError> {
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            return Err(StoreError::InvalidDeviceCredential);
        }
        let (nonce, ciphertext) = encrypt_device_password(password, key)?;
        let now = timestamp();
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET credential_profile='' WHERE identity=?1",
                [identity],
            )
            .map_err(StoreError::Database)?;
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        connection
            .execute(
                "INSERT INTO bmc_device_credentials (
                    identity, username, secret_nonce, secret_ciphertext, key_version, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, ?5)
                 ON CONFLICT(identity) DO UPDATE SET
                    username=excluded.username,
                    secret_nonce=excluded.secret_nonce,
                    secret_ciphertext=excluded.secret_ciphertext,
                    key_version=excluded.key_version,
                    updated_at=excluded.updated_at",
                params![identity, username, nonce, ciphertext, now],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        self.find(identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Decrypts a device secret for an outbound Redfish request. It is deliberately a storage
    /// primitive rather than an API response so browser clients can never retrieve it.
    pub fn device_credential(
        &self,
        identity: &str,
        key: &DeviceCredentialKey,
    ) -> Result<Option<DeviceCredential>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let record: Option<(String, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT username, secret_nonce, secret_ciphertext
                 FROM bmc_device_credentials WHERE identity=?1",
                [identity],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(StoreError::Database)?;
        record
            .map(|(username, nonce, ciphertext)| {
                decrypt_device_password(&nonce, &ciphertext, key)
                    .map(|password| DeviceCredential { username, password })
            })
            .transpose()
    }

    pub fn set_credential_profile(
        &self,
        identity: &str,
        credential_profile: &str,
    ) -> Result<ManagedBmc, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET credential_profile=?2 WHERE identity=?1",
                params![identity, credential_profile],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        self.find(identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Stores a certificate fingerprint only after an explicit operator trust decision.
    /// It is used for subsequent authenticated Redfish requests; no private key or
    /// credential material is retained in SQLite.
    pub fn set_certificate_fingerprint(
        &self,
        identity: &str,
        certificate_fingerprint: &str,
    ) -> Result<ManagedBmc, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET certificate_fingerprint=?2 WHERE identity=?1",
                params![identity, certificate_fingerprint],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
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
        display_name: Option<&str>,
    ) -> Result<ManagedBmc, StoreError> {
        let identity = mac
            .map(str::to_owned)
            .unwrap_or_else(|| format!("manual-{current_ip}"));
        let now = timestamp();
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO managed_bmcs (
                    identity, display_name, mac, scope_id, scope_name, credential_profile, source_ip, current_ip, target_ip,
                    target_prefix, target_gateway, certificate_fingerprint, configuration_status,
                    online_status, redfish_status, authentication_status, last_checked_at,
                    last_configured_at, last_error
                ) VALUES (?1, ?2, ?3, 0, ?4, '', ?5, ?5, ?5, 24, '0.0.0.0', NULL, 'manual',
                          'unknown', 'unknown', 'unknown', NULL, ?6, NULL)
                ON CONFLICT(identity) DO UPDATE SET
                    display_name=excluded.display_name, mac=excluded.mac, scope_name=excluded.scope_name, current_ip=excluded.current_ip",
                params![identity, display_name.unwrap_or(""), mac, scope_name.unwrap_or("手动添加"), current_ip.to_string(), now],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        self.find(&identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Creates a durable copy of a local BMC record. The address is copied as an editable
    /// starting value; the duplicate remains inactive until the operator confirms or changes it.
    /// The MAC is deliberately cleared because it identifies physical hardware.
    pub fn duplicate(&self, source_identity: &str) -> Result<ManagedBmc, StoreError> {
        let source = self
            .find(source_identity)?
            .ok_or(StoreError::MissingRecord)?;
        let identity = format!("draft-{}", Uuid::new_v4());
        let display_name = if source.display_name.trim().is_empty() {
            "BMC 副本".to_owned()
        } else {
            format!("{}-副本", source.display_name.trim())
        };
        let now = timestamp();
        let copied_ip = source.current_ip.to_string();
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        connection
            .execute(
                "INSERT INTO managed_bmcs (
                    identity, display_name, cluster_id, mac, scope_id, scope_name, credential_profile,
                    source_ip, current_ip, target_ip, target_prefix, target_gateway,
                    certificate_fingerprint, configuration_status, online_status, redfish_status,
                    authentication_status, last_checked_at, last_configured_at, last_error
                ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, '', ?6, ?6, ?6, 24, '0.0.0.0', NULL, 'draft',
                          'unknown', 'unknown', 'unknown', NULL, ?7,
                          '确认或修改复制的 BMC IPv4 后开始自动采集与 Redfish 管理')",
                params![
                    identity,
                    display_name,
                    source.cluster_id,
                    source.scope_id as i64,
                    source.scope_name,
                    copied_ip,
                    now,
                ],
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
                "UPDATE managed_bmcs SET current_ip=?2,
                 bmc_mac=CASE WHEN current_ip=?2 THEN bmc_mac ELSE NULL END,
                 serial_number=CASE WHEN current_ip=?2 THEN serial_number ELSE NULL END,
                 hardware_model=CASE WHEN current_ip=?2 THEN hardware_model ELSE NULL END,
                 source_ip=CASE WHEN configuration_status='draft' THEN ?2 ELSE source_ip END,
                 target_ip=CASE WHEN configuration_status='draft' THEN ?2 ELSE target_ip END,
                 configuration_status=CASE WHEN configuration_status='draft' THEN 'manual' ELSE configuration_status END,
                 online_status='unknown', redfish_status='unknown', authentication_status='unknown', last_checked_at=NULL,
                 last_error=CASE WHEN configuration_status='draft' THEN NULL ELSE last_error END
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

    /// Changes the operator-facing server label only. It has no BMC-side effect.
    pub fn update_display_name(
        &self,
        identity: &str,
        display_name: &str,
    ) -> Result<ManagedBmc, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET display_name=?2 WHERE identity=?1",
                params![identity, display_name.trim()],
            )
            .map_err(StoreError::Database)?;
        drop(connection);
        if changed == 0 {
            return Err(StoreError::MissingRecord);
        }
        self.find(identity)?.ok_or(StoreError::MissingRecord)
    }

    /// Re-enable a frozen local item for a deliberate future provisioning run.
    pub fn mark_for_reprovision(&self, identity: &str) -> Result<ManagedBmc, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Lock)?;
        let changed = connection
            .execute(
                "UPDATE managed_bmcs SET configuration_status='pending_reconfiguration',
             online_status='unknown', redfish_status='unknown', authentication_status='unknown',
             last_checked_at=NULL, last_error=NULL WHERE identity=?1",
                [identity],
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
        connection
            .execute(
                "DELETE FROM bmc_device_credentials WHERE identity=?1",
                [identity],
            )
            .map_err(StoreError::Database)?;
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
        display_name: row.get(1)?,
        cluster_id: row.get(2)?,
        mac: row.get(3)?,
        scope_id: row.get::<_, i64>(4)? as u64,
        scope_name: row.get(5)?,
        credential_profile: row.get(6)?,
        credential_username: row.get(7)?,
        credential_updated_at: row.get(8)?,
        source_ip: parse_ip(9)?,
        current_ip: parse_ip(10)?,
        target_network: StaticNetwork {
            address: parse_ip(11)?,
            prefix: row.get::<_, i64>(12)? as u8,
            gateway: parse_ip(13)?,
        },
        certificate_fingerprint: row.get(14)?,
        configuration_status: row.get(15)?,
        online_status: row.get(16)?,
        redfish_status: row.get(17)?,
        authentication_status: row.get(18)?,
        last_checked_at: row.get(19)?,
        last_configured_at: row.get(20)?,
        last_error: row.get(21)?,
        bmc_mac: row.get(22)?,
        serial_number: row.get(23)?,
        hardware_model: row.get(24)?,
    })
}

fn encrypt_device_password(
    password: &str,
    key: &DeviceCredentialKey,
) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| StoreError::CredentialEncryption)?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), password.as_bytes())
        .map_err(|_| StoreError::CredentialEncryption)?;
    Ok((nonce.to_vec(), ciphertext))
}

fn decrypt_device_password(
    nonce: &[u8],
    ciphertext: &[u8],
    key: &DeviceCredentialKey,
) -> Result<String, StoreError> {
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| StoreError::CredentialDecryption)?;
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| StoreError::CredentialDecryption)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| StoreError::CredentialDecryption)?;
    String::from_utf8(plaintext).map_err(|_| StoreError::CredentialDecryption)
}

fn row_to_cluster(row: &rusqlite::Row<'_>) -> rusqlite::Result<BmcCluster> {
    Ok(BmcCluster {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: row.get(2)?,
    })
}

fn identity(candidate: &BmcCandidate) -> String {
    candidate
        .mac
        .clone()
        .unwrap_or_else(|| format!("scope-{}-ip-{}", candidate.scope_id, candidate.ip))
}

fn ensure_managed_bmc_column(
    connection: &Connection,
    column: &str,
    definition: &str,
) -> Result<(), StoreError> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_table_info('managed_bmcs') WHERE name = ?1",
            [column],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::Database)?;
    if exists.is_none() {
        connection
            .execute(
                &format!("ALTER TABLE managed_bmcs ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(StoreError::Database)?;
    }
    Ok(())
}

fn backfill_telemetry_rollups(connection: &Connection) -> Result<(), StoreError> {
    for resolution_seconds in [5 * 60, 60 * 60] {
        connection
            .execute(
                "INSERT INTO bmc_telemetry_rollups (
                    identity, resolution_seconds, window_start, power_watts, power_samples,
                    temperature_celsius, temperature_samples
                 )
                 SELECT identity, ?1, (collected_at / ?1) * ?1,
                    AVG(power_watts), COUNT(power_watts),
                    AVG(temperature_celsius), COUNT(temperature_celsius)
                 FROM bmc_telemetry_history
                 GROUP BY identity, (collected_at / ?1) * ?1
                 ON CONFLICT(identity, resolution_seconds, window_start) DO UPDATE SET
                    power_watts=excluded.power_watts,
                    power_samples=excluded.power_samples,
                    temperature_celsius=excluded.temperature_celsius,
                    temperature_samples=excluded.temperature_samples",
                [resolution_seconds],
            )
            .map_err(StoreError::Database)?;
    }
    Ok(())
}

fn upsert_telemetry_rollup(
    connection: &Connection,
    identity: &str,
    collected_at: i64,
    resolution_seconds: i64,
) -> Result<(), StoreError> {
    let window_start = (collected_at / resolution_seconds) * resolution_seconds;
    connection
        .execute(
            "INSERT INTO bmc_telemetry_rollups (
                identity, resolution_seconds, window_start, power_watts, power_samples,
                temperature_celsius, temperature_samples
             )
             SELECT identity, ?2, ?3,
                AVG(power_watts), COUNT(power_watts),
                AVG(temperature_celsius), COUNT(temperature_celsius)
             FROM bmc_telemetry_history
             WHERE identity = ?1 AND collected_at >= ?3 AND collected_at < ?4
             ON CONFLICT(identity, resolution_seconds, window_start) DO UPDATE SET
                power_watts=excluded.power_watts,
                power_samples=excluded.power_samples,
                temperature_celsius=excluded.temperature_celsius,
                temperature_samples=excluded.temperature_samples",
            params![
                identity,
                resolution_seconds,
                window_start,
                window_start + resolution_seconds
            ],
        )
        .map_err(StoreError::Database)?;
    Ok(())
}

const DATA_DIRECTORY: &str = "bmc-provisioner-data";
const LEGACY_DATA_DIRECTORY: &str = "bmc-provisioner";
const DATABASE_FILE: &str = "inventory.sqlite3";

fn local_application_data_directory() -> Result<PathBuf, StoreError> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .ok_or(StoreError::NoDataDirectory)
}

fn database_path(base: &Path) -> PathBuf {
    base.join(DATA_DIRECTORY).join(DATABASE_FILE)
}

fn legacy_database_path(base: &Path) -> PathBuf {
    base.join(LEGACY_DATA_DIRECTORY).join(DATABASE_FILE)
}

/// Versions up to v0.1.6 stored state alongside the Windows updater's installation files.
/// Copy (rather than move) the old database once so a running legacy process is never disrupted.
fn migrate_legacy_database(base: &Path, destination: &Path) -> Result<(), StoreError> {
    if destination.exists() {
        return Ok(());
    }
    let legacy = legacy_database_path(base);
    if !legacy.is_file() {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(StoreError::Directory)?;
    }
    fs::copy(legacy, destination).map_err(StoreError::Migration)?;
    Ok(())
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
    #[error("could not migrate legacy inventory database")]
    Migration(#[source] std::io::Error),
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
    #[error("device credential username and password are required")]
    InvalidDeviceCredential,
    #[error("could not encrypt the device credential")]
    CredentialEncryption,
    #[error("could not decrypt the device credential; the configured master key may not match")]
    CredentialDecryption,
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
            source: crate::model::CandidateSource::ConfirmedDiscovery,
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
            password_transitioned: false,
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
                "default",
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
                Some("rack-a-server-01"),
            )
            .unwrap();
        assert_eq!(created.configuration_status, "manual");
        assert_eq!(created.display_name, "rack-a-server-01");

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

    #[test]
    fn hardware_identity_survives_partial_scrapes_but_not_address_change() {
        let path = std::env::temp_dir().join(format!("bmc-identity-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let address = Ipv4Addr::new(172, 16, 40, 10);
        let bmc = store
            .add_manual(address, None, None, Some("server"))
            .unwrap();
        store
            .record_hardware_identity(
                &bmc.identity,
                address,
                Some("9c:6b:00:e2:af:06"),
                Some("product-sn"),
                Some("model"),
            )
            .unwrap();
        store
            .record_hardware_identity(&bmc.identity, address, None, Some(" "), None)
            .unwrap();
        assert_eq!(
            store
                .find(&bmc.identity)
                .unwrap()
                .unwrap()
                .serial_number
                .as_deref(),
            Some("product-sn")
        );
        let copy = store.duplicate(&bmc.identity).unwrap();
        assert!(copy.serial_number.is_none());
        assert!(copy.bmc_mac.is_none());
        store.update_address(&bmc.identity, address).unwrap();
        assert_eq!(
            store
                .find(&bmc.identity)
                .unwrap()
                .unwrap()
                .hardware_model
                .as_deref(),
            Some("model")
        );
        store
            .update_address(&bmc.identity, Ipv4Addr::new(172, 16, 40, 11))
            .unwrap();
        store
            .record_hardware_identity(
                &bmc.identity,
                address,
                Some("old"),
                Some("old"),
                Some("old"),
            )
            .unwrap();
        let changed = store.find(&bmc.identity).unwrap().unwrap();
        assert!(
            changed.serial_number.is_none()
                && changed.bmc_mac.is_none()
                && changed.hardware_model.is_none()
        );
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identity_columns_migrate_existing_inventory_without_data_loss() {
        let path = std::env::temp_dir().join(format!("bmc-migration-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let bmc = store
            .add_manual(Ipv4Addr::new(172, 16, 40, 10), None, None, Some("original"))
            .unwrap();
        drop(store);
        let connection = Connection::open(&path).unwrap();
        for column in ["bmc_mac", "serial_number", "hardware_model"] {
            connection
                .execute_batch(&format!("ALTER TABLE managed_bmcs DROP COLUMN {column}"))
                .unwrap();
        }
        drop(connection);
        let store = InventoryStore::open(&path).unwrap();
        let migrated = store.find(&bmc.identity).unwrap().unwrap();
        assert_eq!(migrated.display_name, "original");
        assert!(migrated.bmc_mac.is_none() && migrated.serial_number.is_none());
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn device_credential_is_encrypted_in_sqlite_and_deleted_with_its_bmc() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let managed = store
            .add_manual(
                Ipv4Addr::new(172, 16, 40, 210),
                Some("00:11:22:33:44:66"),
                Some("机房 A"),
                Some("b300-credentials"),
            )
            .unwrap();
        let key = DeviceCredentialKey::new([7; 32]);
        let updated = store
            .save_device_credential(&managed.identity, "admin", "correct-horse-battery", &key)
            .unwrap();

        assert_eq!(updated.credential_username.as_deref(), Some("admin"));
        assert_eq!(updated.credential_profile, "");
        let secret = store
            .device_credential(&managed.identity, &key)
            .unwrap()
            .unwrap();
        assert_eq!(secret.username, "admin");
        assert_eq!(secret.password, "correct-horse-battery");

        let connection = store.connection.lock().unwrap();
        let ciphertext: Vec<u8> = connection
            .query_row(
                "SELECT secret_ciphertext FROM bmc_device_credentials WHERE identity=?1",
                [&managed.identity],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(ciphertext, b"correct-horse-battery");
        drop(connection);

        assert!(
            store
                .device_credential(&managed.identity, &DeviceCredentialKey::new([8; 32]))
                .is_err()
        );
        store.delete(&managed.identity).unwrap();
        assert!(
            store
                .device_credential(&managed.identity, &key)
                .unwrap()
                .is_none()
        );
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn duplicated_bmc_is_persisted_with_an_editable_copied_address_until_confirmed() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let cluster = store.create_cluster("training-a").unwrap();
        let source = store
            .add_manual(
                Ipv4Addr::new(172, 16, 40, 200),
                Some("00:11:22:33:44:55"),
                Some("机房 A"),
                Some("rack-a-server-01"),
            )
            .unwrap();
        store
            .set_cluster(&source.identity, Some(cluster.id))
            .unwrap();
        store
            .set_credential_profile(&source.identity, "rack-a-admin")
            .unwrap();

        let copied = store.duplicate(&source.identity).unwrap();
        assert_ne!(copied.identity, source.identity);
        assert_eq!(copied.display_name, "rack-a-server-01-副本");
        assert_eq!(copied.cluster_id, Some(cluster.id));
        assert_eq!(copied.credential_profile, "");
        assert_eq!(copied.credential_username, None);
        assert_eq!(copied.configuration_status, "draft");
        assert_eq!(copied.current_ip, source.current_ip);
        assert_eq!(copied.mac, None);
        assert!(store.find(&copied.identity).unwrap().is_some());

        let completed = store
            .update_address(&copied.identity, Ipv4Addr::new(172, 16, 40, 201))
            .unwrap();
        assert_eq!(completed.configuration_status, "manual");
        assert_eq!(completed.current_ip, Ipv4Addr::new(172, 16, 40, 201));
        assert_eq!(completed.source_ip, Ipv4Addr::new(172, 16, 40, 201));

        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn clusters_group_bmcs_and_deletion_only_unassigns_members() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let cluster = store.create_cluster("training-a").unwrap();
        let managed = store
            .add_manual(
                Ipv4Addr::new(172, 16, 40, 18),
                Some("00:11:22:33:44:66"),
                Some("manual"),
                Some("b300-01"),
            )
            .unwrap();

        let assigned = store
            .set_cluster(&managed.identity, Some(cluster.id))
            .unwrap();
        assert_eq!(assigned.cluster_id, Some(cluster.id));
        assert_eq!(store.list_clusters().unwrap()[0].name, "training-a");

        let second = store
            .add_manual(
                Ipv4Addr::new(172, 16, 40, 19),
                Some("00:11:22:33:44:67"),
                Some("manual"),
                Some("b300-02"),
            )
            .unwrap();
        store
            .set_cluster_many(
                &[managed.identity.clone(), second.identity.clone()],
                cluster.id,
            )
            .unwrap();
        assert!(
            store
                .list()
                .unwrap()
                .iter()
                .all(|item| item.cluster_id == Some(cluster.id))
        );

        store.delete_cluster(cluster.id).unwrap();
        let retained = store.find(&managed.identity).unwrap().unwrap();
        assert_eq!(retained.cluster_id, None);
        let retained_second = store.find(&second.identity).unwrap().unwrap();
        assert_eq!(retained_second.cluster_id, None);
        assert!(store.list_clusters().unwrap().is_empty());
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn retains_recent_power_and_temperature_history_for_a_managed_bmc() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        let managed = store
            .add_manual(
                Ipv4Addr::new(172, 16, 40, 18),
                Some("00:11:22:33:44:77"),
                Some("manual"),
                Some("b300-telemetry"),
            )
            .unwrap();

        store
            .record_telemetry(&managed.identity, Some(1820.5), Some(58.0))
            .unwrap();
        let points = store
            .telemetry_history(
                &managed.identity,
                timestamp() - 60,
                1,
                TelemetryHistoryResolution::Raw,
            )
            .unwrap();

        assert_eq!(points.len(), 1);
        assert_eq!(points[0].power_watts, Some(1820.5));
        assert_eq!(points[0].temperature_celsius, Some(58.0));
        let rolled = store
            .telemetry_history(
                &managed.identity,
                timestamp() - 60,
                5 * 60,
                TelemetryHistoryResolution::FiveMinutes,
            )
            .unwrap();
        assert_eq!(rolled.len(), 1);
        assert_eq!(rolled[0].power_watts, Some(1820.5));
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn migrates_legacy_database_outside_the_updater_install_directory() {
        let base = std::env::temp_dir().join(format!("bmc-provisioner-data-{}", Uuid::new_v4()));
        let legacy = legacy_database_path(&base);
        let legacy_store = InventoryStore::open(&legacy).unwrap();
        legacy_store
            .save_credential_profiles(&[CredentialProfileMeta {
                name: "rack-a".to_owned(),
                username: "admin".to_owned(),
            }])
            .unwrap();
        drop(legacy_store);

        let destination = database_path(&base);
        migrate_legacy_database(&base, &destination).unwrap();
        assert!(destination.is_file());
        assert!(legacy.is_file());
        let profiles = InventoryStore::open(&destination)
            .unwrap()
            .credential_profiles()
            .unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "rack-a");
        assert_eq!(profiles[0].username, "admin");

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn loads_pre_concurrency_defaults_with_a_safe_parallel_limit() {
        let path = std::env::temp_dir().join(format!("bmc-provisioner-{}.sqlite3", Uuid::new_v4()));
        let store = InventoryStore::open(&path).unwrap();
        store
            .save_setting(
                "provision_defaults",
                &serde_json::json!({
                    "lessorUrl": "http://127.0.0.1:8080",
                    "scopeId": 1,
                    "username": "admin",
                    "targetPrefix": 24,
                    "targetGateway": "10.1.10.254"
                }),
            )
            .unwrap();

        assert_eq!(store.load_defaults().unwrap().batch_concurrency, 4);
        drop(store);
        let _ = fs::remove_file(path);
    }
}
