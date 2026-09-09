use std::net::Ipv4Addr;

use thiserror::Error;
use tokio::time::{Duration, sleep};

use crate::{
    model::{Credentials, ProvisionPlan, ProvisionResult, ProvisionStatus, StaticNetwork},
    redfish::{EthernetInterface, RedfishClient, RedfishError, RedfishInventory},
};

/// Orchestrates a one-BMC change without retaining credentials in its result.
pub struct ProvisionWorkflow;

const VERIFY_ATTEMPTS: u8 = 12;
const VERIFY_INTERVAL: Duration = Duration::from_secs(5);

impl ProvisionWorkflow {
    pub async fn plan(
        source_ip: Ipv4Addr,
        source_mac: Option<&str>,
        credentials: &Credentials,
        target_network: StaticNetwork,
        requested_interface_uri: Option<&str>,
        certificate_fingerprint: Option<&str>,
    ) -> Result<ProvisionPlan, WorkflowError> {
        target_network.validate()?;
        let client = RedfishClient::for_ipv4_with_fingerprint(
            source_ip,
            credentials,
            certificate_fingerprint,
        )?;
        let inventory = client.discover().await?;
        let interface =
            select_interface(&inventory, requested_interface_uri, source_ip, source_mac)?;
        Ok(ProvisionPlan {
            source_ip,
            certificate_fingerprint: certificate_fingerprint.map(ToOwned::to_owned),
            account_uri: inventory.account.uri,
            ethernet_interface_uri: interface.uri,
            current_password_change_required: inventory.account.password_change_required,
            target_network,
        })
    }

    pub async fn apply(
        plan: ProvisionPlan,
        credentials: Credentials,
    ) -> Result<ProvisionResult, WorkflowError> {
        let client = RedfishClient::for_ipv4_with_fingerprint(
            plan.source_ip,
            &credentials,
            plan.certificate_fingerprint.as_deref(),
        )?;
        let inventory = client.discover().await?;
        if inventory.account.uri != plan.account_uri {
            return Err(WorkflowError::PlanChanged(
                "selected account no longer matches the plan",
            ));
        }
        let interface = select_interface(
            &inventory,
            Some(&plan.ethernet_interface_uri),
            plan.source_ip,
            None,
        )?;

        client
            .change_password(&inventory.account, &credentials.new_password)
            .await
            .map_err(WorkflowError::PasswordChange)?;
        let changed_password_client = client.with_password(credentials.new_password);
        changed_password_client
            .configure_static_ipv4(&interface.uri, &plan.target_network)
            .await
            .map_err(WorkflowError::NetworkConfiguration)?;

        // The password stays inside the authenticated client. Network changes can drop the
        // current connection immediately, so an unreachable target is a truthful non-success
        // outcome rather than a fabricated successful verification.
        let verification_client = changed_password_client.at_ipv4(plan.target_network.address)?;
        let status = verify_after_network_change(&verification_client)
            .await
            .map_err(WorkflowError::NetworkVerification)?;

        Ok(ProvisionResult {
            status,
            source_ip: plan.source_ip,
            target_ip: plan.target_network.address,
            account_uri: plan.account_uri,
            ethernet_interface_uri: interface.uri,
        })
    }
}

/// A BMC commonly drops its current HTTPS connection when its IPv4 address changes. Retry only
/// the authenticated Service Root read at a conservative 5-second cadence for at most one minute.
async fn verify_after_network_change(
    client: &RedfishClient,
) -> Result<ProvisionStatus, RedfishError> {
    for attempt in 0..VERIFY_ATTEMPTS {
        match client.verify_connection().await {
            Ok(()) => return Ok(ProvisionStatus::Completed),
            Err(RedfishError::Request(_)) if attempt + 1 < VERIFY_ATTEMPTS => {
                sleep(VERIFY_INTERVAL).await;
            }
            Err(RedfishError::Request(_)) => return Ok(ProvisionStatus::NetworkChangedUnverified),
            Err(error) => return Err(error),
        }
    }
    Ok(ProvisionStatus::NetworkChangedUnverified)
}

fn select_interface(
    inventory: &RedfishInventory,
    requested_interface_uri: Option<&str>,
    source_ip: Ipv4Addr,
    source_mac: Option<&str>,
) -> Result<EthernetInterface, WorkflowError> {
    if let Some(uri) = requested_interface_uri {
        return inventory
            .ethernet_interfaces
            .iter()
            .find(|interface| interface.uri == uri)
            .cloned()
            .ok_or(WorkflowError::PlanChanged(
                "selected EthernetInterface no longer matches the plan",
            ));
    }
    let ip_matches: Vec<_> = inventory
        .ethernet_interfaces
        .iter()
        .filter(|interface| interface.ipv4_addresses.contains(&source_ip))
        .cloned()
        .collect();
    if let [interface] = ip_matches.as_slice() {
        return Ok(interface.clone());
    }
    let normalized_mac = source_mac.map(normalize_mac);
    let mac_matches: Vec<_> = inventory
        .ethernet_interfaces
        .iter()
        .filter(|interface| {
            normalized_mac.as_deref().is_some_and(|source| {
                interface
                    .mac_address
                    .as_deref()
                    .is_some_and(|mac| normalize_mac(mac) == source)
            })
        })
        .cloned()
        .collect();
    if let [interface] = mac_matches.as_slice() {
        return Ok(interface.clone());
    }
    match inventory.ethernet_interfaces.as_slice() {
        [interface] => Ok(interface.clone()),
        interfaces => Err(WorkflowError::InterfaceSelectionRequired(
            interfaces.to_vec(),
        )),
    }
}

fn normalize_mac(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error(transparent)]
    Redfish(#[from] RedfishError),
    #[error("BMC rejected the password-change operation")]
    PasswordChange(#[source] RedfishError),
    #[error("BMC rejected the static IPv4 configuration")]
    NetworkConfiguration(#[source] RedfishError),
    #[error("BMC network changed but Redfish verification failed")]
    NetworkVerification(#[source] RedfishError),
    #[error(transparent)]
    InvalidNetwork(#[from] crate::model::NetworkValidationError),
    #[error("multiple BMC Ethernet interfaces were found; choose one explicitly: {0:?}")]
    InterfaceSelectionRequired(Vec<EthernetInterface>),
    #[error("the BMC changed since the plan was created: {0}")]
    PlanChanged(&'static str),
}
