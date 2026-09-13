use std::net::Ipv4Addr;

use thiserror::Error;
use tokio::{
    sync::mpsc::UnboundedSender,
    time::{Duration, Instant, sleep},
};

use crate::{
    model::{
        Credentials, FirstLoginBootstrap, ProvisionPlan, ProvisionResult, ProvisionStatus,
        StaticNetwork,
    },
    redfish::{
        EthernetInterface, RedfishClient, RedfishError, RedfishInventory,
        ami_web_first_login_supported, reset_ami_web_initial_password,
    },
};

/// Orchestrates a one-BMC change without retaining credentials in its result.
pub struct ProvisionWorkflow;

const VERIFY_DEADLINE: Duration = Duration::from_secs(90);
const VERIFY_FAST_INTERVAL: Duration = Duration::from_secs(2);
const VERIFY_STEADY_INTERVAL: Duration = Duration::from_secs(5);
const VERIFY_FAST_WINDOW: Duration = Duration::from_secs(30);
const FIRST_LOGIN_SETTLE_ATTEMPTS: u8 = 12;
const FIRST_LOGIN_SETTLE_INTERVAL: Duration = Duration::from_secs(2);

/// A workflow event that is safe to show to the operator. It deliberately cannot contain
/// credential material or raw BMC responses.
#[derive(Clone, Debug)]
pub enum WorkflowProgress {
    Message(String),
    /// Static network settings have been accepted. The caller may now release its limited
    /// write slot while this workflow independently waits for Redfish at the new address.
    NetworkChangeSubmitted,
}

impl ProvisionWorkflow {
    pub async fn plan(
        source_ip: Ipv4Addr,
        source_mac: Option<&str>,
        credentials: &Credentials,
        target_network: StaticNetwork,
        requested_interface_uri: Option<&str>,
        certificate_fingerprint: Option<&str>,
        password_change_requested: bool,
    ) -> Result<ProvisionPlan, WorkflowError> {
        target_network.validate()?;
        let client = RedfishClient::for_ipv4_with_fingerprint(
            source_ip,
            credentials,
            certificate_fingerprint,
        )?;
        let inventory = match client.discover().await {
            Ok(inventory) => inventory,
            // A few AMI implementations authenticate an initial account but block Basic-auth
            // access to AccountService until their web UI password transition has completed.
            // Probe the public script signature only after that exact authentication failure.
            Err(RedfishError::AuthenticationFailed) => {
                if credentials.new_password.is_empty() {
                    return Err(WorkflowError::NewPasswordRequired);
                }
                if ami_web_first_login_supported(source_ip, certificate_fingerprint).await? {
                    // A password change can have succeeded even if the previous task lost its
                    // Redfish connection before reaching network configuration. Before trying
                    // the AMI endpoint again, see whether the stored requested new password is
                    // already the active Redfish credential.
                    match client
                        .with_password(credentials.new_password.clone())
                        .discover()
                        .await
                    {
                        Ok(inventory) => {
                            let interface = select_interface(
                                &inventory,
                                requested_interface_uri,
                                source_ip,
                                source_mac,
                            )?;
                            return Ok(ProvisionPlan {
                                source_ip,
                                source_mac: source_mac.map(ToOwned::to_owned),
                                certificate_fingerprint: certificate_fingerprint
                                    .map(ToOwned::to_owned),
                                account_uri: Some(inventory.account.uri),
                                ethernet_interface_uri: Some(interface.uri),
                                current_password_change_required: false,
                                password_change_requested: false,
                                first_login_bootstrap: Some(
                                    FirstLoginBootstrap::AmiPasswordAlreadyChanged,
                                ),
                                target_network,
                            });
                        }
                        Err(RedfishError::AuthenticationFailed) => {}
                        Err(error) => return Err(error.into()),
                    }
                    return Ok(ProvisionPlan {
                        source_ip,
                        source_mac: source_mac.map(ToOwned::to_owned),
                        certificate_fingerprint: certificate_fingerprint.map(ToOwned::to_owned),
                        account_uri: None,
                        ethernet_interface_uri: None,
                        current_password_change_required: true,
                        password_change_requested: true,
                        first_login_bootstrap: Some(FirstLoginBootstrap::AmiWeb),
                        target_network,
                    });
                }
                return Err(WorkflowError::Redfish(RedfishError::AuthenticationFailed));
            }
            Err(error) => return Err(error.into()),
        };
        let interface =
            select_interface(&inventory, requested_interface_uri, source_ip, source_mac)?;
        let password_change_requested =
            password_change_requested || inventory.account.password_change_required;
        if password_change_requested && credentials.new_password.is_empty() {
            return Err(WorkflowError::NewPasswordRequired);
        }
        Ok(ProvisionPlan {
            source_ip,
            source_mac: source_mac.map(ToOwned::to_owned),
            certificate_fingerprint: certificate_fingerprint.map(ToOwned::to_owned),
            account_uri: Some(inventory.account.uri),
            ethernet_interface_uri: Some(interface.uri),
            current_password_change_required: inventory.account.password_change_required,
            password_change_requested,
            first_login_bootstrap: None,
            target_network,
        })
    }

    pub async fn apply(
        plan: ProvisionPlan,
        credentials: Credentials,
    ) -> Result<ProvisionResult, WorkflowError> {
        Self::apply_with_progress(plan, credentials, None).await
    }

    /// Applies a plan while optionally emitting operator-visible, non-sensitive milestones.
    /// Passwords, account URIs and raw BMC response bodies must never be sent here.
    pub async fn apply_with_progress(
        plan: ProvisionPlan,
        credentials: Credentials,
        progress: Option<UnboundedSender<WorkflowProgress>>,
    ) -> Result<ProvisionResult, WorkflowError> {
        report(&progress, "正在连接 BMC Redfish 服务并验证当前凭据");
        let client = RedfishClient::for_ipv4_with_fingerprint(
            plan.source_ip,
            &credentials,
            plan.certificate_fingerprint.as_deref(),
        )?;
        let bootstrap = matches!(
            plan.first_login_bootstrap,
            Some(FirstLoginBootstrap::AmiWeb)
        );
        let password_already_changed = matches!(
            plan.first_login_bootstrap,
            Some(FirstLoginBootstrap::AmiPasswordAlreadyChanged)
        );
        let (client, inventory) = if bootstrap {
            if credentials.new_password.is_empty() {
                return Err(WorkflowError::NewPasswordRequired);
            }
            report(&progress, "检测到首次登录策略，正在完成初始密码变更");
            reset_ami_web_initial_password(
                plan.source_ip,
                &credentials,
                plan.certificate_fingerprint.as_deref(),
            )
            .await
            .map_err(WorkflowError::InitialPasswordBootstrap)?;
            report(&progress, "初始密码变更已提交，正在等待 Redfish 认证就绪");
            let client = client.with_password(credentials.new_password.clone());
            let inventory = discover_after_initial_password_change(&client, &progress).await?;
            (client, inventory)
        } else if password_already_changed {
            report(&progress, "正在使用已更新的密码重新连接 Redfish");
            let client = client.with_password(credentials.new_password.clone());
            let inventory = client.discover().await?;
            (client, inventory)
        } else {
            let inventory = client.discover().await?;
            (client, inventory)
        };

        if let Some(account_uri) = plan.account_uri.as_deref()
            && inventory.account.uri != account_uri
        {
            return Err(WorkflowError::PlanChanged(
                "selected account no longer matches the plan",
            ));
        }
        let interface = select_interface(
            &inventory,
            plan.ethernet_interface_uri.as_deref(),
            plan.source_ip,
            plan.source_mac.as_deref(),
        )?;
        report(&progress, "Redfish 登录成功，已定位 BMC 管理网卡");

        let configured_client = if plan.password_change_requested && !bootstrap {
            report(&progress, "正在修改 BMC 管理员密码");
            client
                .change_password(&inventory.account, &credentials.new_password)
                .await
                .map_err(WorkflowError::PasswordChange)?;
            report(&progress, "BMC 管理员密码已更新");
            client.with_password(credentials.new_password)
        } else {
            client
        };
        report(
            &progress,
            format!(
                "正在写入静态 IPv4 {}/{}，网关 {}",
                plan.target_network.address,
                plan.target_network.prefix,
                plan.target_network.gateway
            ),
        );
        configured_client
            .configure_static_ipv4(&interface.uri, &plan.target_network)
            .await
            .map_err(WorkflowError::NetworkConfiguration)?;
        report_network_change_submitted(&progress);

        // The password stays inside the authenticated client. Network changes can drop the
        // current connection immediately, so an unreachable target is a truthful non-success
        // outcome rather than a fabricated successful verification.
        let verification_client = configured_client.at_ipv4(plan.target_network.address)?;
        let status = verify_after_network_change(&verification_client, &progress)
            .await
            .map_err(WorkflowError::NetworkVerification)?;
        report(
            &progress,
            format!(
                "已在新地址 {} 验证 Redfish 登录",
                plan.target_network.address
            ),
        );

        Ok(ProvisionResult {
            status,
            password_transitioned: bootstrap || password_already_changed,
            source_ip: plan.source_ip,
            target_ip: plan.target_network.address,
            account_uri: inventory.account.uri,
            ethernet_interface_uri: interface.uri,
        })
    }
}

/// AMI may accept its one-time password API before the Redfish account store is ready. Retrying
/// only transient authentication/transport failures avoids treating the successful password
/// transition as a generic pre-change authentication error.
async fn discover_after_initial_password_change(
    client: &RedfishClient,
    progress: &Option<UnboundedSender<WorkflowProgress>>,
) -> Result<RedfishInventory, WorkflowError> {
    for attempt in 0..FIRST_LOGIN_SETTLE_ATTEMPTS {
        match client.discover().await {
            Ok(inventory) => return Ok(inventory),
            Err(RedfishError::AuthenticationFailed | RedfishError::Request(_))
                if attempt + 1 < FIRST_LOGIN_SETTLE_ATTEMPTS =>
            {
                report(
                    progress,
                    format!(
                        "等待 Redfish 认证就绪（第 {}/{} 次）",
                        attempt + 1,
                        FIRST_LOGIN_SETTLE_ATTEMPTS
                    ),
                );
                sleep(FIRST_LOGIN_SETTLE_INTERVAL).await;
            }
            Err(error) => return Err(WorkflowError::PostInitialPasswordChange(error)),
        }
    }
    unreachable!("retry loop returns on the final attempt")
}

/// A BMC commonly drops HTTPS while applying a new IPv4 address. Fast, short probes keep a
/// failed TCP connection from delaying the next check, while a 90-second deadline still allows
/// firmware that restarts its management stack during the change to recover naturally.
async fn verify_after_network_change(
    client: &RedfishClient,
    progress: &Option<UnboundedSender<WorkflowProgress>>,
) -> Result<ProvisionStatus, RedfishError> {
    let started = Instant::now();
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        match client.verify_connection_fast().await {
            Ok(()) => return Ok(ProvisionStatus::Completed),
            Err(RedfishError::Request(_)) if started.elapsed() < VERIFY_DEADLINE => {
                let elapsed = started.elapsed();
                let interval = if elapsed < VERIFY_FAST_WINDOW {
                    VERIFY_FAST_INTERVAL
                } else {
                    VERIFY_STEADY_INTERVAL
                };
                report(
                    progress,
                    format!(
                        "等待新地址 Redfish 重连（第 {attempt} 次，已等待 {} 秒；{} 秒后重试）",
                        elapsed.as_secs(),
                        interval.as_secs(),
                    ),
                );
                sleep(interval).await;
            }
            Err(RedfishError::Request(_)) => return Ok(ProvisionStatus::NetworkChangedUnverified),
            Err(error) => return Err(error),
        }
    }
}

fn report(progress: &Option<UnboundedSender<WorkflowProgress>>, message: impl Into<String>) {
    if let Some(sender) = progress {
        let _ = sender.send(WorkflowProgress::Message(message.into()));
    }
}

fn report_network_change_submitted(progress: &Option<UnboundedSender<WorkflowProgress>>) {
    if let Some(sender) = progress {
        let _ = sender.send(WorkflowProgress::NetworkChangeSubmitted);
    }
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
    #[error("BMC rejected the required initial-password transition")]
    InitialPasswordBootstrap(#[source] RedfishError),
    #[error("BMC password changed, but Redfish did not become ready afterward")]
    PostInitialPasswordChange(#[source] RedfishError),
    #[error("BMC requires an initial password change; provide a new password")]
    NewPasswordRequired,
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
