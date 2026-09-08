use std::{collections::HashMap, net::Ipv4Addr, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use bmc_provisioner::{
    lessor::LessorClient,
    model::{BmcCandidate, Credentials, ProvisionPlan, ProvisionResult, StaticNetwork},
    redfish::{CertificateFingerprint, EthernetInterface, RedfishClient, probe_certificate},
    storage::{InventoryStore, ManagedBmc},
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobRecord {
    id: Uuid,
    state: JobState,
    result: Option<ProvisionResult>,
    error: Option<&'static str>,
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
        .route("/api/v1/managed-bmcs", get(list_managed_bmcs))
        .route(
            "/api/v1/managed-bmcs/{identity}/check",
            post(check_managed_bmc),
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
        &request.credentials,
        request.target_network,
        request.ethernet_interface_uri.as_deref(),
        request.certificate_fingerprint.as_deref(),
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
            if let Err(store_error) = state.inventory.record_provision(
                &candidate,
                &target_network,
                fingerprint.as_deref(),
                None,
                Some("BMC rejected or did not support one of the requested changes"),
            ) {
                tracing::error!(error = %store_error, job_id = %job_id, "could not persist failed BMC inventory");
            }
            update_job(
                &state,
                job_id,
                JobState::Failed,
                None,
                Some("BMC rejected or did not support one of the requested changes"),
            )
            .await;
        }
    }
    *state.active_job.lock().await = false;
}

async fn update_job(
    state: &AppState,
    job_id: Uuid,
    job_state: JobState,
    result: Option<ProvisionResult>,
    error: Option<&'static str>,
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
    if let bmc_provisioner::workflow::WorkflowError::InterfaceSelectionRequired(interfaces) = error
    {
        return ApiError::unprocessable_with_details(
            "multiple BMC Ethernet interfaces were found; select one before applying",
            serde_json::json!({ "ethernetInterfaceUris": interfaces }),
        );
    }
    tracing::warn!(error = %error, "could not build BMC provisioning plan");
    ApiError::unprocessable("BMC could not produce a supported provisioning plan")
}

fn workflow_redfish_api_error(error: bmc_provisioner::redfish::RedfishError) -> ApiError {
    tracing::warn!(error = %error, "could not complete read-only Redfish diagnostic");
    ApiError::unprocessable("BMC could not complete the requested read-only Redfish diagnostic")
}

fn inventory_api_error(error: bmc_provisioner::storage::StoreError) -> ApiError {
    tracing::error!(error = %error, "local BMC inventory operation failed");
    ApiError::internal("could not update local BMC inventory")
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
