use std::{collections::HashMap, net::Ipv4Addr, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch, post},
};
use bmc_provisioner::{
    lessor::LessorClient,
    model::{BmcCandidate, Credentials, ProvisionPlan, ProvisionResult, StaticNetwork},
    redfish::{CertificateFingerprint, EthernetInterface, RedfishClient, probe_certificate},
    storage::{InventoryStore, ManagedBmc, ProvisionDefaults},
    workflow::ProvisionWorkflow,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};
use tracing_subscriber::EnvFilter;
use url::Url;
use uuid::Uuid;

struct AppState {
    plans: Mutex<HashMap<Uuid, PlannedRecord>>,
    jobs: Mutex<HashMap<Uuid, JobRecord>>,
    active_job: Mutex<bool>,
    inventory: InventoryStore,
}

struct PlannedRecord {
    candidate: BmcCandidate,
    plan: ProvisionPlan,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateQuery {
    lessor_url: String,
    scope_id: Option<u64>,
}

/// Kept request-only: its credentials cannot be returned by any API response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanRequest {
    lessor_url: String,
    scope_id: u64,
    candidate_ip: Ipv4Addr,
    credentials: Credentials,
    target_network: StaticNetwork,
    ethernet_interface_uri: Option<String>,
    certificate_fingerprint: Option<String>,
    password_change: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateProbeRequest {
    lessor_url: String,
    scope_id: u64,
    candidate_ip: Ipv4Addr,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateProbeResponse {
    candidate: BmcCandidate,
    fingerprint: CertificateFingerprint,
}

/// Explicitly entered by the operator. This type is accepted only by read-only diagnostic routes;
/// it is deliberately not accepted by provisioning plan/apply routes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KnownStaticBmcRequest {
    bmc_ip: Ipv4Addr,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadOnlyRedfishRequest {
    bmc_ip: Ipv4Addr,
    credentials: ReadOnlyCredentials,
    certificate_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadOnlyCredentials {
    username: String,
    current_password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadOnlyRedfishDiagnostic {
    bmc_ip: Ipv4Addr,
    account_uri: String,
    password_change_required: bool,
    ethernet_interfaces: Vec<ReadOnlyEthernetInterface>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadOnlyEthernetInterface {
    uri: String,
    id: String,
    name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannedProvision {
    plan_id: Uuid,
    candidate: BmcCandidate,
    plan: ProvisionPlan,
}

/// Kept request-only: cached plans never retain credentials.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyRequest {
    credentials: Credentials,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedHealthCheckRequest {
    username: String,
    current_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateManagedBmcRequest {
    current_ip: Ipv4Addr,
    mac: Option<String>,
    scope_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateManagedBmcRequest {
    current_ip: Ipv4Addr,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredCredentials {
    current_password: String,
    new_password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DefaultsResponse {
    defaults: ProvisionDefaults,
    has_stored_credentials: bool,
}

const CREDENTIAL_SERVICE: &str = "io.bmc-provisioner.desktop";
const CREDENTIAL_ACCOUNT: &str = "provision-defaults";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobRecord {
    id: Uuid,
    state: JobState,
    result: Option<ProvisionResult>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
}

#[tokio::main]
async fn main() {
    // `reqwest` and the explicit certificate-pinning path can enable more than one Rustls
    // provider transitively. Pick ring once before any TLS connection, otherwise Rustls 0.23
    // panics when the operator asks to read a BMC's self-signed certificate fingerprint.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install Rustls ring crypto provider");
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state = Arc::new(AppState {
        plans: Mutex::new(HashMap::new()),
        jobs: Mutex::new(HashMap::new()),
        active_job: Mutex::new(false),
        inventory: InventoryStore::open_default().expect("open local BMC inventory"),
    });
    let ui_directory =
        std::env::var("BMC_PROVISIONER_UI_DIR").unwrap_or_else(|_| "ui/dist".to_owned());
    let index = format!("{ui_directory}/index.html");
    let static_ui = ServeDir::new(ui_directory).not_found_service(ServeFile::new(index));
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/api/v1/candidates", get(candidates))
        .route("/api/v1/certificates/probe", post(probe_bmc_certificate))
        .route(
            "/api/v1/diagnostics/redfish/certificate",
            post(probe_known_static_certificate),
        )
        .route(
            "/api/v1/diagnostics/redfish",
            post(read_only_redfish_diagnostic),
        )
        .route("/api/v1/provision/plan", post(plan))
        .route("/api/v1/provision/plans/{plan_id}/apply", post(apply))
        .route("/api/v1/jobs/{job_id}", get(job))
        .route(
            "/api/v1/managed-bmcs",
            get(list_managed_bmcs).post(create_managed_bmc),
        )
        .route(
            "/api/v1/managed-bmcs/{identity}",
            patch(update_managed_bmc).delete(delete_managed_bmc),
        )
        .route(
            "/api/v1/managed-bmcs/{identity}/check",
            post(check_managed_bmc),
        )
        .route(
            "/api/v1/settings/defaults",
            get(load_defaults).put(save_defaults),
        )
        .route(
            "/api/v1/settings/credentials",
            get(load_credentials).post(save_credentials),
        )
        // The service itself only listens on loopback. This permits the Vite development UI to
        // call it from a different loopback port; the packaged desktop UI will be same-origin.
        .layer(CorsLayer::very_permissive())
        .fallback_service(static_ui)
        .with_state(state);
    let address: SocketAddr = std::env::var("BMC_PROVISIONER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:6770".to_owned())
        .parse()
        .expect("BMC_PROVISIONER_BIND must be a socket address");
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind local HTTP server");
    tracing::info!(%address, "bmc-provisionerd listening");
    axum::serve(listener, app)
        .await
        .expect("serve local HTTP server");
}

async fn candidates(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<CandidateQuery>,
) -> Result<Json<Vec<BmcCandidate>>, ApiError> {
    let client = lessor_client(&query.lessor_url)?;
    let candidates = client
        .confirmed_bmcs(query.scope_id)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "could not list confirmed BMC candidates from lessor");
            ApiError::bad_gateway("could not read confirmed BMC candidates from lessor")
        })?;
    Ok(Json(candidates))
}

async fn plan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PlanRequest>,
) -> Result<Json<PlannedProvision>, ApiError> {
    let candidate =
        confirmed_candidate(&request.lessor_url, request.scope_id, request.candidate_ip).await?;

    let provision_plan = ProvisionWorkflow::plan(
        candidate.ip,
        candidate.mac.as_deref(),
        &request.credentials,
        request.target_network,
        request.ethernet_interface_uri.as_deref(),
        request.certificate_fingerprint.as_deref(),
        request.password_change.unwrap_or(false),
    )
    .await
    .map_err(workflow_api_error)?;
    let plan_id = Uuid::new_v4();
    state.plans.lock().await.insert(
        plan_id,
        PlannedRecord {
            candidate: candidate.clone(),
            plan: provision_plan.clone(),
        },
    );
    Ok(Json(PlannedProvision {
        plan_id,
        candidate,
        plan: provision_plan,
    }))
}

async fn probe_bmc_certificate(
    Json(request): Json<CertificateProbeRequest>,
) -> Result<Json<CertificateProbeResponse>, ApiError> {
    let candidate =
        confirmed_candidate(&request.lessor_url, request.scope_id, request.candidate_ip).await?;
    let fingerprint = probe_certificate(candidate.ip).await.map_err(|error| {
        tracing::warn!(error = %error, ip = %candidate.ip, "could not inspect BMC certificate");
        ApiError::unprocessable("could not read a usable HTTPS certificate from this BMC")
    })?;
    Ok(Json(CertificateProbeResponse {
        candidate,
        fingerprint,
    }))
}

/// This does not require a lessor candidate because the IP was explicitly entered by the user.
/// It remains safe: it only completes a TLS handshake and returns a public certificate fingerprint.
async fn probe_known_static_certificate(
    Json(request): Json<KnownStaticBmcRequest>,
) -> Result<Json<CertificateFingerprint>, ApiError> {
    let fingerprint = probe_certificate(request.bmc_ip).await.map_err(|error| {
        tracing::warn!(error = %error, ip = %request.bmc_ip, "could not inspect known BMC certificate");
        ApiError::unprocessable("could not read a usable HTTPS certificate from this BMC")
    })?;
    Ok(Json(fingerprint))
}

/// A read-only escape hatch for BMCs that already have a static address. It constructs no plan,
/// creates no job, and only calls Redfish GET endpoints through `discover`.
async fn read_only_redfish_diagnostic(
    Json(request): Json<ReadOnlyRedfishRequest>,
) -> Result<Json<ReadOnlyRedfishDiagnostic>, ApiError> {
    let credentials = Credentials {
        username: request.credentials.username,
        current_password: request.credentials.current_password,
        new_password: String::new(),
    };
    let client = RedfishClient::for_ipv4_with_fingerprint(
        request.bmc_ip,
        &credentials,
        request.certificate_fingerprint.as_deref(),
    )
    .map_err(workflow_redfish_api_error)?;
    let inventory = client
        .discover()
        .await
        .map_err(workflow_redfish_api_error)?;
    Ok(Json(ReadOnlyRedfishDiagnostic {
        bmc_ip: request.bmc_ip,
        account_uri: inventory.account.uri,
        password_change_required: inventory.account.password_change_required,
        ethernet_interfaces: inventory
            .ethernet_interfaces
            .into_iter()
            .map(ReadOnlyEthernetInterface::from)
            .collect(),
    }))
}

impl From<EthernetInterface> for ReadOnlyEthernetInterface {
    fn from(interface: EthernetInterface) -> Self {
        Self {
            uri: interface.uri,
            id: interface.id,
            name: interface.name,
        }
    }
}

async fn confirmed_candidate(
    lessor_url: &str,
    scope_id: u64,
    candidate_ip: Ipv4Addr,
) -> Result<BmcCandidate, ApiError> {
    let client = lessor_client(lessor_url)?;
    let candidates = client
        .confirmed_bmcs(Some(scope_id))
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "could not validate BMC candidate with lessor");
            ApiError::bad_gateway("could not validate the selected BMC with lessor")
        })?;
    candidates
        .into_iter()
        .find(|candidate| candidate.ip == candidate_ip)
        .ok_or_else(|| {
            ApiError::bad_request("candidateIp is not a currently confirmed BMC in this scope")
        })
}

async fn apply(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<Uuid>,
    Json(request): Json<ApplyRequest>,
) -> Result<(StatusCode, Json<JobRecord>), ApiError> {
    let mut active = state.active_job.lock().await;
    if *active {
        return Err(ApiError::conflict(
            "another BMC provisioning job is already running",
        ));
    }
    let planned = state
        .plans
        .lock()
        .await
        .remove(&plan_id)
        .ok_or_else(|| ApiError::not_found("provisioning plan was not found or has expired"))?;
    *active = true;
    drop(active);

    let job_id = Uuid::new_v4();
    let queued = JobRecord {
        id: job_id,
        state: JobState::Queued,
        result: None,
        error: None,
    };
    state.jobs.lock().await.insert(job_id, queued.clone());

    tokio::spawn(run_job(
        state,
        job_id,
        planned.candidate,
        planned.plan,
        request.credentials,
    ));
    Ok((StatusCode::ACCEPTED, Json(queued)))
}

async fn run_job(
    state: Arc<AppState>,
    job_id: Uuid,
    candidate: BmcCandidate,
    plan: ProvisionPlan,
    credentials: Credentials,
) {
    update_job(&state, job_id, JobState::Running, None, None).await;
    let target_network = plan.target_network.clone();
    let fingerprint = plan.certificate_fingerprint.clone();
    let password_change_requested = plan.password_change_requested;
    match ProvisionWorkflow::apply(plan, credentials).await {
        Ok(result) => {
            if let Err(error) = state.inventory.record_provision(
                &candidate,
                &target_network,
                fingerprint.as_deref(),
                Some(&result),
                None,
            ) {
                tracing::error!(error = %error, job_id = %job_id, "could not persist configured BMC inventory");
            }
            update_job(&state, job_id, JobState::Completed, Some(result), None).await;
        }
        Err(error) => {
            // Do not persist raw BMC response bodies or credentials in a job record.
            tracing::warn!(error = %error, job_id = %job_id, "BMC provisioning job failed");
            let safe_error = provisioning_failure_message(&error, password_change_requested);
            if let Err(store_error) = state.inventory.record_provision(
                &candidate,
                &target_network,
                fingerprint.as_deref(),
                None,
                Some(&safe_error),
            ) {
                tracing::error!(error = %store_error, job_id = %job_id, "could not persist failed BMC inventory");
            }
            update_job(&state, job_id, JobState::Failed, None, Some(safe_error)).await;
        }
    }
    *state.active_job.lock().await = false;
}

fn provisioning_failure_message(
    error: &bmc_provisioner::workflow::WorkflowError,
    password_change_requested: bool,
) -> String {
    use bmc_provisioner::workflow::WorkflowError;
    match error {
        WorkflowError::PasswordChange(_) => {
            "BMC rejected the password change; the network configuration was not attempted"
                .to_owned()
        }
        WorkflowError::NetworkConfiguration(redfish_error) => {
            let password_notice = if password_change_requested {
                "password may have changed; "
            } else {
                ""
            };
            format!(
                "{password_notice}BMC rejected the static IPv4 configuration{}",
                redfish_failure_context(redfish_error)
            )
        }
        WorkflowError::NetworkVerification(_) => {
            if password_change_requested {
                "password and network may have changed, but Redfish verification failed".to_owned()
            } else {
                "network may have changed, but Redfish verification failed".to_owned()
            }
        }
        _ => "BMC provisioning failed before completion; inspect the plan and current BMC state"
            .to_owned(),
    }
}

/// A Redfish MessageId is a fixed protocol identifier, unlike an arbitrary BMC error body.
/// Show it to the operator because it distinguishes a non-writable property from a bad value
/// without exposing credentials or vendor response text.
fn redfish_failure_context(error: &bmc_provisioner::redfish::RedfishError) -> String {
    use bmc_provisioner::redfish::RedfishError;

    match error {
        RedfishError::UnexpectedStatus {
            status,
            message_id: Some(message_id),
        } => format!(" (HTTP {status}; {message_id})"),
        RedfishError::UnexpectedStatus {
            status,
            message_id: None,
        } => format!(" (HTTP {status})"),
        _ => String::new(),
    }
}

async fn update_job(
    state: &AppState,
    job_id: Uuid,
    job_state: JobState,
    result: Option<ProvisionResult>,
    error: Option<String>,
) {
    if let Some(job) = state.jobs.lock().await.get_mut(&job_id) {
        job.state = job_state;
        job.result = result;
        job.error = error;
    }
}

async fn job(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobRecord>, ApiError> {
    let record = state
        .jobs
        .lock()
        .await
        .get(&job_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("job was not found"))?;
    Ok(Json(record))
}

async fn list_managed_bmcs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ManagedBmc>>, ApiError> {
    state.inventory.list().map(Json).map_err(|error| {
        tracing::error!(error = %error, "could not read local BMC inventory");
        ApiError::internal("could not read local BMC inventory")
    })
}

/// Adds an address to the local BMC inventory. This deliberately has no Redfish side effects.
async fn create_managed_bmc(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateManagedBmcRequest>,
) -> Result<(StatusCode, Json<ManagedBmc>), ApiError> {
    let managed = state
        .inventory
        .add_manual(
            request.current_ip,
            request.mac.as_deref(),
            request.scope_name.as_deref(),
        )
        .map_err(inventory_api_error)?;
    Ok((StatusCode::CREATED, Json(managed)))
}

/// Updates the local access address only. Operators use this when an existing BMC was moved
/// outside this tool; it does not reconfigure the controller.
async fn update_managed_bmc(
    State(state): State<Arc<AppState>>,
    Path(identity): Path<String>,
    Json(request): Json<UpdateManagedBmcRequest>,
) -> Result<Json<ManagedBmc>, ApiError> {
    state
        .inventory
        .update_address(&identity, request.current_ip)
        .map(Json)
        .map_err(inventory_api_error)
}

/// Removes an operator's local history row and has no effect on the BMC itself.
async fn delete_managed_bmc(
    State(state): State<Arc<AppState>>,
    Path(identity): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .inventory
        .delete(&identity)
        .map_err(inventory_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn load_defaults(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DefaultsResponse>, ApiError> {
    let defaults = state
        .inventory
        .load_defaults()
        .map_err(inventory_api_error)?;
    Ok(Json(DefaultsResponse {
        defaults,
        has_stored_credentials: stored_credentials()
            .map_err(credential_api_error)?
            .is_some(),
    }))
}

async fn save_defaults(
    State(state): State<Arc<AppState>>,
    Json(defaults): Json<ProvisionDefaults>,
) -> Result<StatusCode, ApiError> {
    state
        .inventory
        .save_defaults(&defaults)
        .map_err(inventory_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn load_credentials() -> Result<Json<StoredCredentials>, ApiError> {
    stored_credentials()
        .map_err(credential_api_error)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no Windows Credential Manager entry was saved"))
}

async fn save_credentials(
    Json(credentials): Json<StoredCredentials>,
) -> Result<StatusCode, ApiError> {
    let payload = serde_json::to_string(&credentials)
        .map_err(|_| ApiError::unprocessable("could not encode credentials"))?;
    keyring::Entry::new(CREDENTIAL_SERVICE, CREDENTIAL_ACCOUNT)
        .and_then(|entry| entry.set_password(&payload))
        .map_err(credential_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn stored_credentials() -> Result<Option<StoredCredentials>, keyring::Error> {
    let entry = keyring::Entry::new(CREDENTIAL_SERVICE, CREDENTIAL_ACCOUNT)?;
    match entry.get_password() {
        Ok(value) => Ok(serde_json::from_str(&value).ok()),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Checks a persisted BMC without retaining the supplied credential. A TLS handshake establishes
/// reachability first; authenticated Redfish discovery then distinguishes usable credentials.
async fn check_managed_bmc(
    State(state): State<Arc<AppState>>,
    Path(identity): Path<String>,
    Json(request): Json<ManagedHealthCheckRequest>,
) -> Result<Json<ManagedBmc>, ApiError> {
    let managed = state
        .inventory
        .find(&identity)
        .map_err(inventory_api_error)?
        .ok_or_else(|| ApiError::not_found("managed BMC was not found"))?;
    if probe_certificate(managed.current_ip).await.is_err() {
        return state
            .inventory
            .record_health(
                &identity,
                "offline",
                "unreachable",
                "unknown",
                Some("HTTPS connection failed"),
            )
            .map(Json)
            .map_err(inventory_api_error);
    }
    let credentials = Credentials {
        username: request.username,
        current_password: request.current_password,
        new_password: String::new(),
    };
    let client = RedfishClient::for_ipv4_with_fingerprint(
        managed.current_ip,
        &credentials,
        managed.certificate_fingerprint.as_deref(),
    )
    .map_err(workflow_redfish_api_error)?;
    let health = match client.discover().await {
        Ok(_) => ("online", "reachable", "success", None),
        Err(error) => {
            tracing::warn!(error = %error, ip = %managed.current_ip, "managed BMC health check could not authenticate");
            (
                "online",
                "reachable",
                "failed",
                Some("Redfish authentication or discovery failed"),
            )
        }
    };
    state
        .inventory
        .record_health(&identity, health.0, health.1, health.2, health.3)
        .map(Json)
        .map_err(inventory_api_error)
}

fn lessor_client(lessor_url: &str) -> Result<LessorClient, ApiError> {
    let url = Url::parse(lessor_url)
        .map_err(|_| ApiError::bad_request("lessorUrl must be a valid URL"))?;
    LessorClient::new(url).map_err(|_| ApiError::bad_request("lessorUrl must use http or https"))
}

fn workflow_api_error(error: bmc_provisioner::workflow::WorkflowError) -> ApiError {
    use bmc_provisioner::{redfish::RedfishError, workflow::WorkflowError};

    match error {
        WorkflowError::InterfaceSelectionRequired(interfaces) => {
            ApiError::unprocessable_with_details(
                "multiple BMC Ethernet interfaces could not be distinguished; select one explicitly",
                serde_json::json!({ "ethernetInterfaces": interfaces }),
            )
        }
        WorkflowError::Redfish(RedfishError::AuthenticationFailed) => ApiError::unprocessable(
            "BMC authentication failed; check the current username and password",
        ),
        WorkflowError::Redfish(RedfishError::AccountNotFound(_)) => ApiError::unprocessable(
            "BMC accepted the connection but did not expose the selected Redfish account",
        ),
        WorkflowError::Redfish(RedfishError::NoManager) => {
            ApiError::unprocessable("BMC Redfish did not expose a Manager resource")
        }
        WorkflowError::Redfish(RedfishError::NoEthernetInterfaces) => {
            ApiError::unprocessable("BMC Redfish did not expose a configurable EthernetInterface")
        }
        WorkflowError::Redfish(RedfishError::Request(_)) => ApiError::unprocessable(
            "could not reach or verify BMC HTTPS; read and confirm its certificate fingerprint",
        ),
        WorkflowError::Redfish(RedfishError::Decode(_)) => {
            ApiError::unprocessable("BMC returned an unsupported Redfish resource format")
        }
        WorkflowError::InvalidNetwork(_) => {
            ApiError::bad_request("target IPv4, prefix, or gateway is invalid")
        }
        WorkflowError::PlanChanged(_) => ApiError::unprocessable(
            "BMC Redfish resources changed; refresh the plan and select the interface again",
        ),
        other => {
            tracing::warn!(error = %other, "could not build BMC provisioning plan");
            ApiError::unprocessable_with_details(
                "BMC could not produce a supported provisioning plan",
                // `Display` for these typed errors contains only the local failure class or HTTP
                // status; it never includes a password or an unbounded BMC response body.
                serde_json::json!({ "reason": other.to_string() }),
            )
        }
    }
}

fn workflow_redfish_api_error(error: bmc_provisioner::redfish::RedfishError) -> ApiError {
    tracing::warn!(error = %error, "could not complete read-only Redfish diagnostic");
    ApiError::unprocessable("BMC could not complete the requested read-only Redfish diagnostic")
}

fn inventory_api_error(error: bmc_provisioner::storage::StoreError) -> ApiError {
    if matches!(error, bmc_provisioner::storage::StoreError::MissingRecord) {
        return ApiError::not_found("managed BMC was not found");
    }
    tracing::error!(error = %error, "local BMC inventory operation failed");
    ApiError::internal("could not update local BMC inventory")
}

fn credential_api_error(error: keyring::Error) -> ApiError {
    tracing::warn!(error = %error, "Windows Credential Manager operation failed");
    ApiError::unprocessable("could not access Windows Credential Manager")
}

struct ApiError {
    status: StatusCode,
    message: &'static str,
    details: Option<serde_json::Value>,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
            details: None,
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
            details: None,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
            details: None,
        }
    }

    fn unprocessable(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message,
            details: None,
        }
    }

    fn unprocessable_with_details(message: &'static str, details: serde_json::Value) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message,
            details: Some(details),
        }
    }

    fn bad_gateway(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
            details: None,
        }
    }

    fn internal(message: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
            details: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let mut body = serde_json::json!({ "error": self.message });
        if let Some(details) = self.details {
            body["details"] = details;
        }
        (self.status, Json(body)).into_response()
    }
}
