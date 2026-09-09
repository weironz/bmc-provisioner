use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How this row entered the provisioning inventory.
///
/// A relay DHCP binding only says that a client with this MAC holds the address;
/// the Redfish plan step still has to confirm it is a manageable BMC before any
/// write is attempted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CandidateSource {
    ConfirmedDiscovery,
    RelayDhcpLease,
}

/// A BMC confirmed by lessor discovery, or a Relay DHCP candidate pending
/// Redfish confirmation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BmcCandidate {
    pub scope_id: u64,
    pub scope_name: String,
    pub subnet: Ipv4Addr,
    pub prefix: u8,
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub source: CandidateSource,
}

/// The desired static IPv4 configuration for the BMC management interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticNetwork {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
}

impl StaticNetwork {
    pub fn validate(&self) -> Result<(), NetworkValidationError> {
        if self.prefix == 0 || self.prefix > 32 {
            return Err(NetworkValidationError::InvalidPrefix(self.prefix));
        }
        if self.address.is_unspecified()
            || self.address.is_multicast()
            || self.address.is_broadcast()
        {
            return Err(NetworkValidationError::InvalidAddress(self.address));
        }
        if self.gateway.is_unspecified()
            || self.gateway.is_multicast()
            || self.gateway.is_broadcast()
        {
            return Err(NetworkValidationError::InvalidGateway(self.gateway));
        }
        Ok(())
    }

    pub fn subnet_mask(&self) -> [u8; 4] {
        let mask = u32::MAX
            .checked_shl(u32::from(32 - self.prefix))
            .unwrap_or(0);
        mask.to_be_bytes()
    }

    pub fn subnet_mask_string(&self) -> String {
        Ipv4Addr::from(self.subnet_mask()).to_string()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NetworkValidationError {
    #[error("IPv4 prefix must be between 1 and 32, got {0}")]
    InvalidPrefix(u8),
    #[error("target address is not a usable unicast IPv4 address: {0}")]
    InvalidAddress(Ipv4Addr),
    #[error("gateway is not a usable unicast IPv4 address: {0}")]
    InvalidGateway(Ipv4Addr),
}

/// Request-only credential material. It intentionally cannot be serialized or debug-printed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub username: String,
    pub current_password: String,
    pub new_password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("username", &self.username)
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// Public, password-free description of the Redfish resources to be changed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionPlan {
    pub source_ip: Ipv4Addr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_fingerprint: Option<String>,
    pub account_uri: String,
    pub ethernet_interface_uri: String,
    pub current_password_change_required: bool,
    pub password_change_requested: bool,
    pub target_network: StaticNetwork,
}

/// Result safe to retain in an API job record or display in a UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProvisionStatus {
    Completed,
    NetworkChangedUnverified,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub status: ProvisionStatus,
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub account_uri: String,
    pub ethernet_interface_uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_prefix_to_subnet_mask() {
        let network = StaticNetwork {
            address: Ipv4Addr::new(192, 168, 1, 20),
            prefix: 24,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
        };

        assert_eq!(network.subnet_mask_string(), "255.255.255.0");
    }

    #[test]
    fn rejects_unspecified_target_ip() {
        let network = StaticNetwork {
            address: Ipv4Addr::UNSPECIFIED,
            prefix: 24,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
        };

        assert_eq!(
            network.validate(),
            Err(NetworkValidationError::InvalidAddress(
                Ipv4Addr::UNSPECIFIED
            ))
        );
    }

    #[test]
    fn credentials_debug_output_is_redacted() {
        let credentials = Credentials {
            username: "admin".to_owned(),
            current_password: "old-secret".to_owned(),
            new_password: "new-secret".to_owned(),
        };

        let debug = format!("{credentials:?}");
        assert!(debug.contains("admin"));
        assert!(!debug.contains("old-secret"));
        assert!(!debug.contains("new-secret"));
    }
}
