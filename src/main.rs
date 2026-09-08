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

#[derive(Default)]
struct AppState {
    plans: Mutex<HashMap<Uuid, ProvisionPlan>>,
    jobs: Mutex<HashMap<Uuid, JobRecord>>,
    active_job: Mutex<bool>,
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

    let state = Arc::new(AppState::default());
    let ui_directory =
        std::env::var("BMC_PROVISIONER_UI_DIR").unwrap_or_else(|_| "ui/dist".to_owned());
    let index = format!("{ui_directory}/index.html");
    let static_ui = ServeDir::new(ui_directory).not_found_service(ServeFile::new(index));
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/api/v1/candidates", get(candidates))
        .route("/api/v1/provision/plan", post(plan))
        .route("/api/v1/provision/plans/{plan_id}/apply", post(apply))
        .route("/api/v1/jobs/{job_id}", get(job))
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
    let client = lessor_client(&request.lessor_url)?;
    let candidates = client
        .confirmed_bmcs(Some(request.scope_id))
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "could not validate BMC candidate with lessor");
            ApiError::bad_gateway("could not validate the selected BMC with lessor")
        })?;
    let candidate = candidates
        .into_iter()
        .find(|candidate| candidate.ip == request.candidate_ip)
        .ok_or_else(|| {
            ApiError::bad_request("candidateIp is not a currently confirmed BMC in this scope")
        })?;

    let provision_plan = ProvisionWorkflow::plan(
        candidate.ip,
        &request.credentials,
        request.target_network,
        request.ethernet_interface_uri.as_deref(),
    )
    .await
    .map_err(workflow_api_error)?;
    let plan_id = Uuid::new_v4();
    state
        .plans
        .lock()
        .await
        .insert(plan_id, provision_plan.clone());
    Ok(Json(PlannedProvision {
        plan_id,
        candidate,
        plan: provision_plan,
    }))
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
    let plan = state
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

    tokio::spawn(run_job(state, job_id, plan, request.credentials));
    Ok((StatusCode::ACCEPTED, Json(queued)))
}

async fn run_job(
    state: Arc<AppState>,
    job_id: Uuid,
    plan: ProvisionPlan,
    credentials: Credentials,
) {
    update_job(&state, job_id, JobState::Running, None, None).await;
    match ProvisionWorkflow::apply(plan, credentials).await {
        Ok(result) => update_job(&state, job_id, JobState::Completed, Some(result), None).await,
        Err(error) => {
            // Do not persist raw BMC response bodies or credentials in a job record.
            tracing::warn!(error = %error, job_id = %job_id, "BMC provisioning job failed");
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
