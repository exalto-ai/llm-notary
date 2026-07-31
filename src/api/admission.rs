use std::{
    env, fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tracing::Span;
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, DatabasePool, database_error, publish::PublishJobRow,
    unix_timestamp,
};
use certified::{
    archive::extract_trace_package_archive,
    bundle::{trace_package_created_at_unix_ms, trace_package_notary_key, verify_trace_package},
    public::{ProviderProvenance, TLSNOTARY_PROVENANCE, platform_key_id, stamp_trace},
    sha256_hex, validate_disclosed_http_redactions,
};

const ADMISSION_INTERVAL_SECS: u64 = 2;
const METADATA_INTERVAL_SECS: u64 = 10;
const CLAIM_TIMEOUT_SECS: i64 = 15 * 60;
const MAX_JOBS_PER_TICK: usize = 4;
const MAX_METADATA_PER_TICK: usize = 4;
const METADATA_RETRY_SECS: i64 = 60 * 60;
const METADATA_CLAIM_TIMEOUT_SECS: i64 = 5 * 60;
const RECENT_DOWNLOAD_WINDOW_SECS: i64 = 28 * 24 * 60 * 60;
const METADATA_MODEL: &str = "gpt-5.6-luna";
const METADATA_PROMPT_VERSION: &str = "library-metadata/v1";
const DEFAULT_METADATA_WEEKLY_BUDGET_CENTS: i64 = 1_000;
const DEFAULT_METADATA_INPUT_NANOUSD_PER_TOKEN: i64 = 200;
const DEFAULT_METADATA_CACHED_INPUT_NANOUSD_PER_TOKEN: i64 = 20;
const DEFAULT_METADATA_CACHE_WRITE_NANOUSD_PER_TOKEN: i64 = 250;
const DEFAULT_METADATA_OUTPUT_NANOUSD_PER_TOKEN: i64 = 1_200;
const MAX_METADATA_PROMPT_TOKENS: i64 = 32_000;
const MAX_METADATA_COMPLETION_TOKENS: i64 = 256;
const NANOUSD_PER_CENT: i64 = 10_000_000;
const SECS_PER_WEEK: i64 = 7 * 24 * 60 * 60;
const ALLOWED_TAGS: &[&str] = &[
    "agent",
    "classification",
    "coding",
    "direct-api",
    "streaming",
    "structured-output",
    "summarization",
    "tests",
    "tool-call",
    "tool-result",
];

#[derive(FromRow)]
struct PublicArtifactRow {
    id: String,
    public_trace_object_key: String,
    public_trace_size_bytes: i64,
    public_trace_sha256: String,
    public_stamp_object_key: String,
    public_stamp_size_bytes: i64,
    public_stamp_sha256: String,
}

#[derive(Serialize)]
struct PublicTraceMetadata {
    id: String,
    trace_url: String,
    stamp_url: String,
}

#[derive(Serialize)]
struct PlatformDirectory {
    format: &'static str,
    issuer: String,
    key_id: String,
    public_key: String,
}

#[derive(FromRow)]
struct LibraryRow {
    id: String,
    github_login: String,
    admitted_at: i64,
    public_trace_object_key: String,
    public_trace_size_bytes: i64,
    public_trace_sha256: String,
    public_stamp_object_key: String,
    public_stamp_size_bytes: i64,
    public_stamp_sha256: String,
    title: Option<String>,
    tags_json: Option<String>,
    recent_downloads: i64,
}

#[derive(Serialize)]
struct CollectionResponse {
    format: &'static str,
    slug: String,
    title: String,
    description: String,
    consent_label: &'static str,
    publications: Vec<CollectionPublication>,
}

#[derive(Serialize)]
struct CollectionPublication {
    id: String,
    title: String,
    tool_use: bool,
    tags: Vec<String>,
    author: String,
    admitted_at: i64,
    provider: String,
    host: String,
    model: String,
    span_count: usize,
    recent_downloads: i64,
    trace_url: String,
    stamp_url: String,
}

#[derive(Clone)]
pub struct MetadataService {
    api_key: Option<String>,
    model: String,
    weekly_budget_nanousd: i64,
    input_nanousd_per_token: i64,
    cached_input_nanousd_per_token: i64,
    cache_write_nanousd_per_token: i64,
    output_nanousd_per_token: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedMetadata {
    title: String,
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
    usage: ChatUsage,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: i64,
    #[serde(default)]
    prompt_tokens_details: ChatPromptTokenDetails,
    completion_tokens: i64,
}

#[derive(Default, Deserialize)]
struct ChatPromptTokenDetails {
    #[serde(default)]
    cached_tokens: i64,
    #[serde(default)]
    cache_write_tokens: i64,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityRequest {
    subject: String,
}

impl MetadataService {
    pub fn from_env() -> Self {
        let weekly_budget_cents = positive_env_i64(
            "LLM_NOTARY_LIBRARY_METADATA_WEEKLY_BUDGET_CENTS",
            DEFAULT_METADATA_WEEKLY_BUDGET_CENTS,
        );
        Self {
            api_key: env::var("OPENAI_API_KEY")
                .ok()
                .filter(|value| !value.is_empty()),
            model: env::var("LLM_NOTARY_LIBRARY_METADATA_MODEL")
                .unwrap_or_else(|_| METADATA_MODEL.to_owned()),
            weekly_budget_nanousd: weekly_budget_cents.saturating_mul(NANOUSD_PER_CENT),
            input_nanousd_per_token: positive_env_i64(
                "LLM_NOTARY_LIBRARY_METADATA_INPUT_NANOUSD_PER_TOKEN",
                DEFAULT_METADATA_INPUT_NANOUSD_PER_TOKEN,
            ),
            cached_input_nanousd_per_token: positive_env_i64(
                "LLM_NOTARY_LIBRARY_METADATA_CACHED_INPUT_NANOUSD_PER_TOKEN",
                DEFAULT_METADATA_CACHED_INPUT_NANOUSD_PER_TOKEN,
            ),
            cache_write_nanousd_per_token: positive_env_i64(
                "LLM_NOTARY_LIBRARY_METADATA_CACHE_WRITE_NANOUSD_PER_TOKEN",
                DEFAULT_METADATA_CACHE_WRITE_NANOUSD_PER_TOKEN,
            ),
            output_nanousd_per_token: positive_env_i64(
                "LLM_NOTARY_LIBRARY_METADATA_OUTPUT_NANOUSD_PER_TOKEN",
                DEFAULT_METADATA_OUTPUT_NANOUSD_PER_TOKEN,
            ),
        }
    }

    async fn generate(
        &self,
        http: &reqwest::Client,
        database: &DatabasePool,
        trace: &[u8],
    ) -> Result<Option<GeneratedMetadata>> {
        let Some(api_key) = &self.api_key else {
            return Ok(None);
        };
        let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
        let period_start = weekly_period_start(now);
        let spent: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(estimated_cost_nanousd), 0)
             FROM library_metadata_usage WHERE period_start = $1",
        )
        .bind(period_start)
        .fetch_one(database)
        .await?;
        if spent.saturating_add(self.max_request_nanousd()) > self.weekly_budget_nanousd {
            tracing::warn!(
                spent_nanousd = spent,
                weekly_budget_nanousd = self.weekly_budget_nanousd,
                "Library metadata weekly budget is exhausted"
            );
            return Ok(None);
        }
        let trace_excerpt: String = String::from_utf8_lossy(trace)
            .chars()
            .take(24_000)
            .collect();
        let body = serde_json::json!({
            "model": self.model,
            "max_completion_tokens": MAX_METADATA_COMPLETION_TOKENS,
            "store": false,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "library_metadata",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["title", "tags"],
                        "properties": {
                            "title": {"type": "string", "minLength": 1, "maxLength": 96},
                            "tags": {
                                "type": "array",
                                "maxItems": 4,
                                "items": {"type": "string", "enum": ALLOWED_TAGS}
                            }
                        }
                    }
                }
            },
            "messages": [
                {"role": "system", "content": "Create terse Library metadata for a published LLM trace. Title: 3 to 8 words, sentence case, simple present tense, active voice, and starts with the actor (for example, Agent, Model, or API). Avoid gerunds, noun phrases, and task-specific subject matter; describe the interaction method only. Tags: choose zero to four schema tags directly supported by the trace. Use exactly one origin tag: agent for an agent workflow, direct-api for a direct provider API workflow; never use both, and do not infer direct-api merely because a provider request occurs. Use tool-call when the model requests a tool and tool-result when a tool result is supplied; use both only when both events appear. Do not quote, paraphrase, or expose prompt/response content, names, credentials, personal data, or secrets."},
                {"role": "user", "content": format!("Public trace excerpt ({}):\n{}", METADATA_PROMPT_VERSION, trace_excerpt)}
            ]
        });
        let response = http
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(api_key)
            .json(&body)
            .timeout(Duration::from_secs(20))
            .send()
            .await?
            .error_for_status()?;
        let response: ChatCompletionResponse = response.json().await?;
        let estimated_cost_nanousd = self.estimated_cost_nanousd(&response.usage)?;
        sqlx::query(
            "INSERT INTO library_metadata_usage
                 (period_start, model, prompt_tokens, cached_prompt_tokens,
                  cache_write_tokens, completion_tokens,
                  estimated_cost_nanousd, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(period_start)
        .bind(&self.model)
        .bind(response.usage.prompt_tokens)
        .bind(response.usage.prompt_tokens_details.cached_tokens)
        .bind(response.usage.prompt_tokens_details.cache_write_tokens)
        .bind(response.usage.completion_tokens)
        .bind(estimated_cost_nanousd)
        .bind(now)
        .execute(database)
        .await?;
        let content = response
            .choices
            .into_iter()
            .next()
            .and_then(|choice| choice.message.content)
            .ok_or_else(|| anyhow::anyhow!("metadata model returned no message content"))?;
        let metadata: GeneratedMetadata = serde_json::from_str(&content)?;
        validate_generated_metadata(&metadata)?;
        Ok(Some(metadata))
    }

    fn max_request_nanousd(&self) -> i64 {
        MAX_METADATA_PROMPT_TOKENS
            .saturating_mul(self.input_nanousd_per_token)
            .saturating_add(
                MAX_METADATA_COMPLETION_TOKENS.saturating_mul(self.output_nanousd_per_token),
            )
    }

    fn estimated_cost_nanousd(&self, usage: &ChatUsage) -> Result<i64> {
        if usage.prompt_tokens < 0
            || usage.prompt_tokens_details.cached_tokens < 0
            || usage.prompt_tokens_details.cache_write_tokens < 0
            || usage.completion_tokens < 0
            || usage.prompt_tokens_details.cached_tokens
                + usage.prompt_tokens_details.cache_write_tokens
                > usage.prompt_tokens
        {
            bail!("metadata model returned negative token usage");
        }
        let uncached_input_tokens = usage.prompt_tokens
            - usage.prompt_tokens_details.cached_tokens
            - usage.prompt_tokens_details.cache_write_tokens;
        Ok(usage
            .prompt_tokens_details
            .cached_tokens
            .saturating_mul(self.cached_input_nanousd_per_token)
            .saturating_add(
                usage
                    .prompt_tokens_details
                    .cache_write_tokens
                    .saturating_mul(self.cache_write_nanousd_per_token),
            )
            .saturating_add(uncached_input_tokens.saturating_mul(self.input_nanousd_per_token))
            .saturating_add(
                usage
                    .completion_tokens
                    .saturating_mul(self.output_nanousd_per_token),
            ))
    }
}

fn positive_env_i64(name: &str, default: i64) -> i64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn weekly_period_start(timestamp: i64) -> i64 {
    timestamp - timestamp.rem_euclid(SECS_PER_WEEK)
}

enum AdmissionFailure {
    Reject(&'static str, anyhow::Error),
    Retry(anyhow::Error),
}

struct AdmittedArtifacts {
    trace: Vec<u8>,
    stamp: Vec<u8>,
}

struct StoredPublicArtifacts {
    trace_object_key: String,
    trace_size_bytes: i64,
    trace_sha256: String,
    stamp_object_key: String,
    stamp_size_bytes: i64,
    stamp_sha256: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/platform", get(platform_directory))
        .route("/api/public/collections/examples", get(examples_collection))
        .route(
            "/api/public/traces/{trace_id}/events/download",
            post(record_download_event),
        )
        .route("/api/public/traces/{trace_id}", get(public_trace_metadata))
        .route(
            "/api/public/traces/{trace_id}/trace.otlp.json",
            get(public_trace),
        )
        .route(
            "/api/public/traces/{trace_id}/stamp.json",
            get(public_stamp),
        )
}

async fn examples_collection(State(state): State<AppState>) -> ApiResult<Json<CollectionResponse>> {
    let now = unix_timestamp()?;
    let rows: Vec<LibraryRow> = sqlx::query_as(
        "SELECT publish_jobs.id, users.github_login, publish_jobs.admitted_at,
                publish_jobs.public_trace_object_key, publish_jobs.public_trace_size_bytes,
                publish_jobs.public_trace_sha256, publish_jobs.public_stamp_object_key,
                publish_jobs.public_stamp_size_bytes, publish_jobs.public_stamp_sha256,
                publication_metadata.title, publication_metadata.tags_json,
                COUNT(publication_activity_events.id) AS recent_downloads
         FROM publish_jobs
         JOIN users ON users.id = publish_jobs.user_id
         LEFT JOIN publication_metadata ON publication_metadata.publication_id = publish_jobs.id
         LEFT JOIN publication_activity_events ON publication_activity_events.publication_id = publish_jobs.id
             AND publication_activity_events.event_type = 'download'
             AND publication_activity_events.occurred_at >= $1
         WHERE publish_jobs.state = 'admitted'
           AND publish_jobs.public_trace_object_key IS NOT NULL
           AND publish_jobs.public_stamp_object_key IS NOT NULL
         GROUP BY publish_jobs.id, users.github_login,
                  publication_metadata.title, publication_metadata.tags_json
         ORDER BY recent_downloads DESC, publish_jobs.admitted_at DESC, publish_jobs.id DESC",
    )
    .bind(now - RECENT_DOWNLOAD_WINDOW_SECS)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    let mut publications = Vec::with_capacity(rows.len());
    for row in rows {
        publications.push(collection_publication(&state, row).await?);
    }
    Ok(Json(CollectionResponse {
        format: "llm-notary/public-collection/v1",
        slug: "llm-notary-library".to_owned(),
        title: "LLM Notary Library".to_owned(),
        description: "Admitted, independently verifiable LLM traces.".to_owned(),
        consent_label: "Consent-based publication",
        publications,
    }))
}

async fn collection_publication(
    state: &AppState,
    artifact: LibraryRow,
) -> ApiResult<CollectionPublication> {
    let (trace, stamp) = tokio::try_join!(
        load_public_bytes(
            state,
            &artifact.public_trace_object_key,
            artifact.public_trace_size_bytes,
            &artifact.public_trace_sha256,
        ),
        load_public_bytes(
            state,
            &artifact.public_stamp_object_key,
            artifact.public_stamp_size_bytes,
            &artifact.public_stamp_sha256,
        ),
    )?;
    let stamp: certified::public::PublicStamp =
        serde_json::from_slice(&stamp).map_err(|error| ApiError::internal(error.into()))?;
    let (model, span_count, tool_use) = trace_facts(&trace).map_err(ApiError::internal)?;
    let tags = artifact
        .tags_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| ApiError::internal(error.into()))?
        .unwrap_or_default();
    Ok(CollectionPublication {
        id: artifact.id.clone(),
        title: artifact
            .title
            .unwrap_or_else(|| fallback_title(&stamp.provider.name, &model)),
        tool_use,
        tags,
        author: artifact.github_login,
        admitted_at: artifact.admitted_at,
        provider: stamp.provider.name,
        host: stamp.provider.host,
        model,
        span_count,
        recent_downloads: artifact.recent_downloads,
        trace_url: format!("/api/public/traces/{}/trace.otlp.json", artifact.id),
        stamp_url: format!("/api/public/traces/{}/stamp.json", artifact.id),
    })
}

fn trace_facts(trace: &[u8]) -> Result<(String, usize, bool)> {
    let value: serde_json::Value = serde_json::from_slice(trace)?;
    let spans = value
        .pointer("/resourceSpans/0/scopeSpans/0/spans")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("public trace has no span array"))?;
    let first = spans
        .first()
        .and_then(|span| span.get("attributes"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("public trace has no span attributes"))?;
    let model = first
        .iter()
        .find(|attribute| {
            attribute.get("key").and_then(serde_json::Value::as_str) == Some("gen_ai.request.model")
        })
        .and_then(|attribute| attribute.pointer("/value/stringValue"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("public trace has no request model"))?;
    let tool_use = spans.iter().try_fold(false, |found, span| {
        let attributes = span
            .get("attributes")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("public trace span has no attributes"))?;
        attributes
            .iter()
            .filter(|attribute| {
                matches!(
                    attribute.get("key").and_then(serde_json::Value::as_str),
                    Some("gen_ai.input.messages" | "gen_ai.output.messages")
                )
            })
            .try_fold(found, |found, attribute| {
                let messages = attribute
                    .pointer("/value/stringValue")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        anyhow::anyhow!("public trace message attribute is not a string")
                    })?;
                let messages: serde_json::Value = serde_json::from_str(messages)?;
                Ok::<_, anyhow::Error>(found || contains_tool_part(&messages))
            })
    })?;
    Ok((model.to_owned(), spans.len(), tool_use))
}

fn contains_tool_part(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(contains_tool_part),
        serde_json::Value::Object(values) => {
            matches!(
                values.get("type").and_then(serde_json::Value::as_str),
                Some("tool_call" | "tool_call_response")
            ) || values.values().any(contains_tool_part)
        }
        _ => false,
    }
}

fn fallback_title(provider: &str, model: &str) -> String {
    format!("{provider} {model} trace")
}

fn validate_generated_metadata(metadata: &GeneratedMetadata) -> Result<()> {
    let title = metadata.title.trim();
    if title.is_empty()
        || title.chars().count() > 96
        || title.chars().any(char::is_control)
        || metadata.tags.len() > 4
        || metadata
            .tags
            .iter()
            .any(|tag| !ALLOWED_TAGS.contains(&tag.as_str()))
    {
        bail!("metadata model returned invalid Library metadata");
    }
    if metadata.tags.iter().any(|tag| tag == "agent")
        && metadata.tags.iter().any(|tag| tag == "direct-api")
    {
        bail!("metadata model returned conflicting origin tags");
    }
    let unique = metadata
        .tags
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != metadata.tags.len() {
        bail!("metadata model returned duplicate Library tags");
    }
    Ok(())
}

async fn record_download_event(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
    Json(request): Json<ActivityRequest>,
) -> ApiResult<StatusCode> {
    let subject = Uuid::parse_str(&request.subject)
        .ok()
        .filter(|parsed| parsed.hyphenated().to_string() == request.subject)
        .ok_or_else(|| ApiError::bad_request("activity subject must be a lowercase UUID"))?;
    load_public_artifact(&state, &trace_id).await?;
    let now = unix_timestamp()?;
    sqlx::query(
        "INSERT INTO publication_activity_events
             (publication_id, event_type, subject_key_sha256, occurred_at)
         VALUES ($1, 'download', $2, $3)
         ON CONFLICT (publication_id, event_type, subject_key_sha256) DO NOTHING",
    )
    .bind(trace_id)
    .bind(sha256_hex(subject.to_string().as_bytes()))
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn platform_directory(State(state): State<AppState>) -> ApiResult<Json<PlatformDirectory>> {
    let key =
        state.publish.platform_signing_key.as_ref().ok_or_else(|| {
            ApiError::service_unavailable("publication signing is not configured")
        })?;
    Ok(Json(PlatformDirectory {
        format: "llm-notary/platform-directory/v1",
        issuer: state.publish.stamp_issuer.clone(),
        key_id: platform_key_id(key.verifying_key()),
        public_key: hex::encode(key.verifying_key().to_sec1_bytes()),
    }))
}

pub fn spawn(state: AppState) {
    if !state.publish.enabled() {
        return;
    }
    let metadata_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(METADATA_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if let Err(error) = backfill_library_metadata(&metadata_state).await {
                tracing::error!(%error, "backfilling Library metadata failed");
            }
        }
    });
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(ADMISSION_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if let Err(error) = recover_stale_claims(&state).await {
                tracing::error!(%error, "recovering stale publication claims failed");
                continue;
            }
            if let Err(error) = purge_admitted_private_objects(&state).await {
                tracing::error!(%error, "purging admitted private objects failed");
            }
            if let Err(error) = update_queue_metrics(&state).await {
                tracing::error!(%error, "updating publication admission metrics failed");
            }
            for _ in 0..MAX_JOBS_PER_TICK {
                match claim_next_job(&state).await {
                    Ok(Some((job, claim))) => process_claim(&state, job, claim).await,
                    Ok(None) => break,
                    Err(error) => {
                        tracing::error!(%error, "claiming publication job failed");
                        break;
                    }
                }
            }
        }
    });
}

async fn update_queue_metrics(state: &AppState) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let (count, oldest): (i64, Option<i64>) =
        sqlx::query_as("SELECT COUNT(*), MIN(queued_at) FROM publish_jobs WHERE state = 'queued'")
            .fetch_one(&state.database)
            .await?;
    metrics::gauge!("llm_notary_admission_queue_depth").set(count as f64);
    metrics::gauge!("llm_notary_admission_oldest_queued_seconds").set(
        oldest
            .map(|queued_at| now.saturating_sub(queued_at) as f64)
            .unwrap_or(0.0),
    );
    Ok(())
}

async fn backfill_library_metadata(state: &AppState) -> Result<()> {
    if state.library_metadata.api_key.is_none() {
        return Ok(());
    }
    for _ in 0..MAX_METADATA_PER_TICK {
        let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
        let Some((artifact, claim)) = claim_next_metadata_artifact(state, now).await? else {
            break;
        };
        let trace = load_public_bytes(
            state,
            &artifact.public_trace_object_key,
            artifact.public_trace_size_bytes,
            &artifact.public_trace_sha256,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.message))?;
        let fallback = trace_facts(&trace)
            .ok()
            .map(|(model, _, _)| fallback_title("Verified", &model))
            .unwrap_or_else(|| "Verified LLM trace".to_owned());
        let generated = match state
            .library_metadata
            .generate(&state.http, &state.database, &trace)
            .await
        {
            Ok(Some(metadata)) => Some(metadata),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(job_id = %artifact.id, %error, "Library metadata generation failed");
                None
            }
        };
        let (title, tags, source, generator_model, generated_at) = match generated {
            Some(metadata) => (
                metadata.title.trim().to_owned(),
                metadata.tags,
                "generated",
                Some(state.library_metadata.model.clone()),
                Some(now),
            ),
            None => (fallback, Vec::new(), "fallback", None, None),
        };
        let updated = sqlx::query(
            "UPDATE publication_metadata
             SET title = $1, tags_json = $2, title_source = $3, generator_model = $4,
                 generator_prompt_version = $5, generated_at = $6,
                 last_generation_attempt_at = $7, updated_at = $8,
                 generation_claim = NULL, generation_claimed_at = NULL
             WHERE publication_id = $9 AND generation_claim = $10",
        )
        .bind(title)
        .bind(serde_json::to_string(&tags)?)
        .bind(source)
        .bind(generator_model)
        .bind(METADATA_PROMPT_VERSION)
        .bind(generated_at)
        .bind(now)
        .bind(now)
        .bind(&artifact.id)
        .bind(&claim)
        .execute(&state.database)
        .await?;
        if updated.rows_affected() != 1 {
            tracing::warn!(job_id = %artifact.id, "Library metadata claim was lost before completion");
        }
    }
    Ok(())
}

async fn claim_next_metadata_artifact(
    state: &AppState,
    now: i64,
) -> Result<Option<(PublicArtifactRow, String)>> {
    let claim = Uuid::new_v4().to_string();
    let artifact = sqlx::query_as::<_, PublicArtifactRow>(
        "WITH candidate AS (
                 SELECT jobs.id
                 FROM publish_jobs AS jobs
                 LEFT JOIN publication_metadata AS metadata
                   ON metadata.publication_id = jobs.id
                 WHERE jobs.state = 'admitted'
                   AND jobs.public_trace_object_key IS NOT NULL
                   AND jobs.public_stamp_object_key IS NOT NULL
                   AND (
                        metadata.publication_id IS NULL
                        OR (
                            metadata.title_source = 'fallback'
                            AND COALESCE(metadata.last_generation_attempt_at, 0) <= $1
                            AND (
                                metadata.generation_claim IS NULL
                                OR metadata.generation_claimed_at < $2
                            )
                        )
                   )
                 ORDER BY jobs.admitted_at ASC
                 FOR UPDATE OF jobs SKIP LOCKED
                 LIMIT 1
             ), claimed AS (
                 INSERT INTO publication_metadata
                     (publication_id, title, tags_json, title_source, generator_model,
                      generator_prompt_version, generated_at, last_generation_attempt_at,
                      updated_at, generation_claim, generation_claimed_at)
                 SELECT candidate.id, 'Verified LLM trace', '[]', 'fallback', NULL, NULL,
                        NULL, $3, $3, $4, $3
                 FROM candidate
                 ON CONFLICT (publication_id) DO UPDATE
                    SET generation_claim = EXCLUDED.generation_claim,
                        generation_claimed_at = EXCLUDED.generation_claimed_at
                  WHERE publication_metadata.title_source = 'fallback'
                    AND (
                        publication_metadata.generation_claim IS NULL
                        OR publication_metadata.generation_claimed_at < $2
                    )
                 RETURNING publication_id
             )
             SELECT jobs.id, jobs.public_trace_object_key, jobs.public_trace_size_bytes,
                    jobs.public_trace_sha256, jobs.public_stamp_object_key,
                    jobs.public_stamp_size_bytes, jobs.public_stamp_sha256
             FROM claimed
             JOIN publish_jobs AS jobs ON jobs.id = claimed.publication_id",
    )
    .bind(now - METADATA_RETRY_SECS)
    .bind(now - METADATA_CLAIM_TIMEOUT_SECS)
    .bind(now)
    .bind(&claim)
    .fetch_optional(&state.database)
    .await?;
    Ok(artifact.map(|artifact| (artifact, claim)))
}

async fn claim_next_job(state: &AppState) -> Result<Option<(PublishJobRow, String)>> {
    let claim = Uuid::new_v4().to_string();
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let job = sqlx::query_as::<_, PublishJobRow>(
        "WITH next_job AS (
                 SELECT id FROM publish_jobs
                 WHERE state = 'queued'
                 ORDER BY queued_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
             )
             UPDATE publish_jobs
             SET state = 'verifying', verification_claim = $1, verification_started_at = $2,
                 updated_at = $3, failure_code = NULL
             FROM next_job
             WHERE publish_jobs.id = next_job.id
             RETURNING publish_jobs.*",
    )
    .bind(&claim)
    .bind(now)
    .bind(now)
    .fetch_optional(&state.database)
    .await?;
    Ok(job.map(|job| (job, claim)))
}

#[tracing::instrument(
    name = "publication.admission",
    skip_all,
    fields(publication.job_id = %job.id, archive.size_bytes = tracing::field::Empty)
)]
async fn process_claim(state: &AppState, job: PublishJobRow, claim: String) {
    let started = Instant::now();
    let archive = match state
        .publish
        .storage
        .get_object(
            &job.intake_object_key,
            state.publish.max_archive_bytes as usize,
        )
        .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            reject_claim(state, &job, &claim, "object_missing", None).await;
            finish_admission_metric("rejected", started);
            return;
        }
        Err(error) => {
            retry_claim(state, &job, &claim, error).await;
            finish_admission_metric("retry", started);
            return;
        }
    };
    let actual_size = archive.len() as i64;
    Span::current().record("archive.size_bytes", actual_size);
    metrics::histogram!("llm_notary_admission_archive_bytes").record(actual_size as f64);
    let actual_sha256 = sha256_hex(&archive);
    if actual_size != job.declared_size_bytes {
        reject_claim(
            state,
            &job,
            &claim,
            "object_size_mismatch",
            Some((actual_size, actual_sha256)),
        )
        .await;
        finish_admission_metric("rejected", started);
        return;
    }
    if actual_sha256 != job.declared_sha256 {
        reject_claim(
            state,
            &job,
            &claim,
            "object_sha256_mismatch",
            Some((actual_size, actual_sha256)),
        )
        .await;
        finish_admission_metric("rejected", started);
        return;
    }

    let directory = state.notary_directory.clone();
    let signing_key = state
        .publish
        .platform_signing_key
        .clone()
        .expect("enabled publication service has a platform signing key");
    let issuer = state.publish.stamp_issuer.clone();
    let job_id = job.id.clone();
    let issued_at = job.queued_at.unwrap_or(job.updated_at).max(0) as u64 * 1000;
    let parent = Span::current();
    let result = tokio::task::spawn_blocking(move || {
        parent.in_scope(|| {
            verify_and_stamp(
                &job_id,
                &archive,
                &directory,
                &signing_key,
                issuer,
                issued_at,
            )
        })
    })
    .await;
    match result {
        Ok(Ok(artifacts)) => {
            if let Err(error) =
                admit_claim(state, &job, &claim, actual_size, &actual_sha256, artifacts).await
            {
                retry_claim(state, &job, &claim, error).await;
                finish_admission_metric("retry", started);
            } else {
                finish_admission_metric("admitted", started);
            }
        }
        Ok(Err(AdmissionFailure::Reject(code, error))) => {
            tracing::info!(job_id = %job.id, failure_code = code, %error, "publication rejected");
            reject_claim(
                state,
                &job,
                &claim,
                code,
                Some((actual_size, actual_sha256)),
            )
            .await;
            finish_admission_metric("rejected", started);
        }
        Ok(Err(AdmissionFailure::Retry(error))) => {
            retry_claim(state, &job, &claim, error).await;
            finish_admission_metric("retry", started);
        }
        Err(error) => {
            retry_claim(state, &job, &claim, anyhow::anyhow!(error)).await;
            finish_admission_metric("retry", started);
        }
    }
}

fn finish_admission_metric(outcome: &'static str, started: Instant) {
    metrics::counter!("llm_notary_admission_jobs_total", "outcome" => outcome).increment(1);
    metrics::histogram!("llm_notary_admission_duration_seconds", "outcome" => outcome)
        .record(started.elapsed().as_secs_f64());
}

fn verify_and_stamp(
    job_id: &str,
    archive: &[u8],
    directory: &certified::notary_directory::NotaryDirectory,
    signing_key: &k256::ecdsa::SigningKey,
    issuer: String,
    issued_at_unix_ms: u64,
) -> std::result::Result<AdmittedArtifacts, AdmissionFailure> {
    let workspace = AdmissionWorkspace::new(job_id)
        .map_err(|error| AdmissionFailure::Retry(error.context("creating admission workspace")))?;
    extract_trace_package_archive(archive, &workspace.package)
        .map_err(|error| AdmissionFailure::Reject("archive_invalid", error))?;
    let embedded_key = trace_package_notary_key(&workspace.package)
        .map_err(|error| AdmissionFailure::Reject("package_invalid", error))?;
    let authenticated_at = trace_package_created_at_unix_ms(&workspace.package)
        .map_err(|error| AdmissionFailure::Reject("package_invalid", error))?;
    let record = directory
        .notaries
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(&embedded_key))
        })
        .ok_or_else(|| {
            AdmissionFailure::Reject(
                "notary_untrusted",
                anyhow::anyhow!("package notary is absent from the server directory"),
            )
        })?;
    if !record.trusted_at(authenticated_at) {
        return Err(AdmissionFailure::Reject(
            "notary_untrusted",
            anyhow::anyhow!("package notary is not trusted at its authenticated timestamp"),
        ));
    }
    let trusted_key = record
        .public_key_bytes()
        .map_err(|error| AdmissionFailure::Retry(error.context("reading trusted notary key")))?;
    let manifest = verify_trace_package(&workspace.package, &trusted_key)
        .map_err(|error| AdmissionFailure::Reject("package_invalid", error))?;
    let request = fs::read(workspace.package.join("request.disclosed.http"))
        .map_err(|error| AdmissionFailure::Retry(error.into()))?;
    let response = fs::read(workspace.package.join("response.http"))
        .map_err(|error| AdmissionFailure::Retry(error.into()))?;
    validate_disclosed_http_redactions(&request, &response)
        .map_err(|error| AdmissionFailure::Reject("sensitive_header_disclosed", error))?;
    let trace = fs::read(workspace.package.join("trace.otlp.json"))
        .map_err(|error| AdmissionFailure::Retry(error.into()))?;
    let stamp = stamp_trace(
        &trace,
        issuer,
        issued_at_unix_ms,
        ProviderProvenance {
            evidence: TLSNOTARY_PROVENANCE.to_owned(),
            host: manifest.provider_host().to_owned(),
            name: manifest.provider_name().to_owned(),
        },
        signing_key,
    )
    .map_err(|error| AdmissionFailure::Retry(error.context("signing public trace")))?;
    let mut stamp =
        serde_json::to_vec_pretty(&stamp).map_err(|error| AdmissionFailure::Retry(error.into()))?;
    stamp.push(b'\n');
    Ok(AdmittedArtifacts { trace, stamp })
}

async fn admit_claim(
    state: &AppState,
    job: &PublishJobRow,
    claim: &str,
    actual_size: i64,
    actual_sha256: &str,
    artifacts: AdmittedArtifacts,
) -> Result<()> {
    let stored = store_public_artifacts(state, &job.id, &artifacts).await?;
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let update = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'admitted', actual_size_bytes = $1, actual_sha256 = $2,
             admitted_at = $3, updated_at = $4,
             public_trace_object_key = $5, public_trace_size_bytes = $6,
             public_trace_sha256 = $7, public_stamp_object_key = $8,
             public_stamp_size_bytes = $9, public_stamp_sha256 = $10,
             verification_claim = NULL
         WHERE id = $11 AND state = 'verifying' AND verification_claim = $12
           AND public_trace_object_key IS NULL AND public_stamp_object_key IS NULL",
    )
    .bind(actual_size)
    .bind(actual_sha256)
    .bind(now)
    .bind(now)
    .bind(&stored.trace_object_key)
    .bind(stored.trace_size_bytes)
    .bind(&stored.trace_sha256)
    .bind(&stored.stamp_object_key)
    .bind(stored.stamp_size_bytes)
    .bind(&stored.stamp_sha256)
    .bind(&job.id)
    .bind(claim)
    .execute(&state.database)
    .await;
    match update {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            let current = load_public_artifact(state, &job.id).await.ok();
            if !current
                .as_ref()
                .is_some_and(|current| current.matches(&stored))
            {
                delete_public_artifacts(state, &stored).await;
                bail!("publication claim was lost before admission");
            }
        }
        Err(error) => {
            // A database error can make commit status ambiguous. Retain the
            // content-addressed candidates so a successful commit never points
            // at deleted objects; a later retry overwrites the same bytes.
            return Err(error.into());
        }
    }
    purge_private_object(state, job).await;
    Ok(())
}

async fn store_public_artifacts(
    state: &AppState,
    trace_id: &str,
    artifacts: &AdmittedArtifacts,
) -> Result<StoredPublicArtifacts> {
    let trace_sha256 = sha256_hex(&artifacts.trace);
    let stamp_sha256 = sha256_hex(&artifacts.stamp);
    let stored = StoredPublicArtifacts {
        trace_object_key: state.publish.storage.public_artifact_key(
            trace_id,
            "trace",
            &trace_sha256,
        )?,
        trace_size_bytes: artifacts.trace.len().try_into()?,
        trace_sha256,
        stamp_object_key: state.publish.storage.public_artifact_key(
            trace_id,
            "stamp",
            &stamp_sha256,
        )?,
        stamp_size_bytes: artifacts.stamp.len().try_into()?,
        stamp_sha256,
    };
    if let Err(error) = write_public_artifact(
        state,
        &stored.trace_object_key,
        "trace",
        &stored.trace_sha256,
        &artifacts.trace,
    )
    .await
    {
        delete_public_artifacts(state, &stored).await;
        return Err(error);
    }
    if let Err(error) = write_public_artifact(
        state,
        &stored.stamp_object_key,
        "stamp",
        &stored.stamp_sha256,
        &artifacts.stamp,
    )
    .await
    {
        delete_public_artifacts(state, &stored).await;
        return Err(error);
    }
    Ok(stored)
}

async fn write_public_artifact(
    state: &AppState,
    object_key: &str,
    kind: &str,
    sha256: &str,
    bytes: &[u8],
) -> Result<()> {
    state
        .publish
        .storage
        .put_public_artifact(object_key, kind, sha256, bytes)
        .await?;
    let stored = state
        .publish
        .storage
        .head_object(object_key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("public artifact disappeared after upload"))?;
    if !super::intake::IntakeStorage::has_expected_public_metadata(
        &stored,
        kind,
        sha256,
        bytes.len().try_into()?,
    ) {
        bail!("public artifact metadata changed after upload");
    }
    Ok(())
}

async fn delete_public_artifacts(state: &AppState, artifacts: &StoredPublicArtifacts) {
    for object_key in [&artifacts.trace_object_key, &artifacts.stamp_object_key] {
        if let Err(error) = state.publish.storage.delete_object(object_key).await {
            tracing::error!(%object_key, %error, "deleting uncommitted public artifact failed");
        }
    }
}

impl PublicArtifactRow {
    fn matches(&self, stored: &StoredPublicArtifacts) -> bool {
        self.public_trace_object_key == stored.trace_object_key
            && self.public_trace_size_bytes == stored.trace_size_bytes
            && self.public_trace_sha256 == stored.trace_sha256
            && self.public_stamp_object_key == stored.stamp_object_key
            && self.public_stamp_size_bytes == stored.stamp_size_bytes
            && self.public_stamp_sha256 == stored.stamp_sha256
    }
}

async fn reject_claim(
    state: &AppState,
    job: &PublishJobRow,
    claim: &str,
    code: &'static str,
    actual: Option<(i64, String)>,
) {
    let now = unix_timestamp().unwrap_or(job.updated_at);
    let (actual_size, actual_sha256) = actual
        .map(|(size, sha256)| (Some(size), Some(sha256)))
        .unwrap_or((None, None));
    match sqlx::query(
        "UPDATE publish_jobs
         SET state = 'rejected', failure_code = $1, actual_size_bytes = $2,
             actual_sha256 = $3, updated_at = $4, verification_claim = NULL
         WHERE id = $5 AND state = 'verifying' AND verification_claim = $6",
    )
    .bind(code)
    .bind(actual_size)
    .bind(actual_sha256)
    .bind(now)
    .bind(&job.id)
    .bind(claim)
    .execute(&state.database)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => purge_private_object(state, job).await,
        Ok(_) => tracing::warn!(job_id = %job.id, "publication rejection lost its claim"),
        Err(error) => tracing::error!(job_id = %job.id, %error, "recording rejection failed"),
    }
}

async fn retry_claim(state: &AppState, job: &PublishJobRow, claim: &str, error: anyhow::Error) {
    tracing::error!(job_id = %job.id, %error, "publication admission will retry");
    let now = unix_timestamp().unwrap_or(job.updated_at);
    if let Err(update_error) = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'queued', updated_at = $1, verification_claim = NULL,
             verification_started_at = NULL
         WHERE id = $2 AND state = 'verifying' AND verification_claim = $3",
    )
    .bind(now)
    .bind(&job.id)
    .bind(claim)
    .execute(&state.database)
    .await
    {
        tracing::error!(job_id = %job.id, %update_error, "requeueing publication failed");
    }
}

async fn purge_private_object(state: &AppState, job: &PublishJobRow) {
    match state
        .publish
        .storage
        .delete_object(&job.intake_object_key)
        .await
    {
        Ok(()) => {
            let now = unix_timestamp().unwrap_or(job.updated_at);
            if let Err(error) = sqlx::query(
                "UPDATE publish_jobs SET private_purged_at = $1, updated_at = $2
                 WHERE id = $3 AND private_purged_at IS NULL",
            )
            .bind(now)
            .bind(now)
            .bind(&job.id)
            .execute(&state.database)
            .await
            {
                tracing::error!(job_id = %job.id, %error, "recording private purge failed");
            }
        }
        Err(error) => tracing::error!(job_id = %job.id, %error, "private object purge failed"),
    }
}

async fn purge_admitted_private_objects(state: &AppState) -> Result<()> {
    let jobs = sqlx::query_as::<_, PublishJobRow>(
        "SELECT * FROM publish_jobs
         WHERE state IN ('admitted', 'rejected') AND private_purged_at IS NULL
         ORDER BY updated_at LIMIT 100",
    )
    .fetch_all(&state.database)
    .await?;
    for job in jobs {
        purge_private_object(state, &job).await;
    }
    Ok(())
}

async fn recover_stale_claims(state: &AppState) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let cutoff = now - CLAIM_TIMEOUT_SECS;
    sqlx::query(
        "UPDATE publish_jobs
         SET state = 'queued', verification_claim = NULL,
             verification_started_at = NULL, updated_at = $1
         WHERE state = 'verifying' AND verification_started_at < $2
           AND public_trace_object_key IS NULL
           AND public_stamp_object_key IS NULL",
    )
    .bind(now)
    .bind(cutoff)
    .execute(&state.database)
    .await?;
    Ok(())
}

async fn load_public_artifact(state: &AppState, trace_id: &str) -> ApiResult<PublicArtifactRow> {
    load_public_artifact_optional(state, trace_id)
        .await?
        .ok_or_else(|| ApiError::not_found("public trace was not found"))
}

async fn load_public_artifact_optional(
    state: &AppState,
    trace_id: &str,
) -> ApiResult<Option<PublicArtifactRow>> {
    sqlx::query_as(
        "SELECT publish_jobs.id, publish_jobs.public_trace_object_key,
                publish_jobs.public_trace_size_bytes,
                publish_jobs.public_trace_sha256,
                publish_jobs.public_stamp_object_key,
                publish_jobs.public_stamp_size_bytes,
                publish_jobs.public_stamp_sha256
         FROM publish_jobs
         WHERE publish_jobs.id = $1 AND publish_jobs.state = 'admitted'
           AND publish_jobs.public_trace_object_key IS NOT NULL
           AND publish_jobs.public_stamp_object_key IS NOT NULL",
    )
    .bind(trace_id)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)
}

async fn public_trace_metadata(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
) -> ApiResult<Json<PublicTraceMetadata>> {
    let artifact = load_public_artifact(&state, &trace_id).await?;
    Ok(Json(PublicTraceMetadata {
        id: artifact.id.clone(),
        trace_url: format!("/api/public/traces/{}/trace.otlp.json", artifact.id),
        stamp_url: format!("/api/public/traces/{}/stamp.json", artifact.id),
    }))
}

async fn public_trace(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
) -> ApiResult<Response> {
    let artifact = load_public_artifact(&state, &trace_id).await?;
    let bytes = load_public_bytes(
        &state,
        &artifact.public_trace_object_key,
        artifact.public_trace_size_bytes,
        &artifact.public_trace_sha256,
    )
    .await?;
    Ok(public_bytes(bytes, "application/json; charset=utf-8"))
}

async fn public_stamp(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
) -> ApiResult<Response> {
    let artifact = load_public_artifact(&state, &trace_id).await?;
    let bytes = load_public_bytes(
        &state,
        &artifact.public_stamp_object_key,
        artifact.public_stamp_size_bytes,
        &artifact.public_stamp_sha256,
    )
    .await?;
    Ok(public_bytes(bytes, "application/json; charset=utf-8"))
}

async fn load_public_bytes(
    state: &AppState,
    object_key: &str,
    size_bytes: i64,
    sha256: &str,
) -> ApiResult<Vec<u8>> {
    let limit: usize = size_bytes
        .try_into()
        .map_err(|_| ApiError::service_unavailable("public artifact metadata is invalid"))?;
    let bytes = state
        .publish
        .storage
        .get_object(object_key, limit)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::service_unavailable("public artifact is temporarily unavailable")
        })?;
    if bytes.len() != limit || sha256_hex(&bytes) != sha256 {
        return Err(ApiError::service_unavailable(
            "public artifact failed its integrity check",
        ));
    }
    Ok(bytes)
}

fn public_bytes(bytes: Vec<u8>, content_type: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Body::from(bytes),
    )
        .into_response()
}

struct AdmissionWorkspace {
    root: PathBuf,
    package: PathBuf,
}

impl AdmissionWorkspace {
    fn new(job_id: &str) -> Result<Self> {
        if !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("job ID is unsafe for an admission workspace");
        }
        let root = std::env::temp_dir().join(format!(
            "llm-notary-admission-{job_id}-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&root)?;
        let package = root.join("package");
        Ok(Self { root, package })
    }
}

impl Drop for AdmissionWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::super::intake::MockIntakeStorage;
    use super::super::publish::PublishService;
    use super::*;

    async fn test_state() -> (AppState, MockIntakeStorage) {
        let database = super::super::fresh_database().await;
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'publisher', 1, 1)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let storage = MockIntakeStorage::new();
        (
            AppState {
                database: database.pool.clone(),
                _test_database: Some(database),
                http: reqwest::Client::new(),
                github_client_id: "client-id".to_owned(),
                github_client_secret: "secret".to_owned(),
                callback_url: Url::parse("https://example.com/callback").unwrap(),
                app_url: Url::parse("https://example.com").unwrap(),
                secure_cookies: true,
                notary_directory: super::super::tests::directory_key(),
                publish: PublishService::mock(storage.clone()),
                library_metadata: MetadataService::from_env(),
            },
            storage,
        )
    }

    async fn queued_job(state: &AppState, bytes: &[u8], sha256: &str) -> PublishJobRow {
        sqlx::query(
            "INSERT INTO publish_jobs
             (id, user_id, idempotency_key, state, archive_format,
              declared_size_bytes, declared_sha256, upload_object_key,
              intake_object_key, upload_expires_at, created_at, updated_at, queued_at)
             VALUES ('job-1', 'user-1', 'idempotency-key-0001', 'queued', $1,
                     $2, $3, 'upload-key', 'intake-key', 1000, 1, 1, 1)",
        )
        .bind(certified::archive::ARCHIVE_FORMAT)
        .bind(bytes.len() as i64)
        .bind(sha256)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query_as("SELECT * FROM publish_jobs WHERE id = 'job-1'")
            .fetch_one(&state.database)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn atomic_claim_allows_only_one_worker() {
        let (state, _) = test_state().await;
        queued_job(&state, b"archive", &sha256_hex(b"archive")).await;
        assert!(claim_next_job(&state).await.unwrap().is_some());
        assert!(claim_next_job(&state).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn library_lists_all_admitted_records_without_a_source_allowlist() {
        let (state, _) = test_state().await;
        let response = examples_collection(State(state)).await.unwrap().0;
        assert_eq!(response.slug, "llm-notary-library");
        assert!(response.publications.is_empty());
    }

    #[test]
    fn collection_tool_use_comes_from_authenticated_trace_messages() {
        let trace = serde_json::json!({
            "resourceSpans": [{
                "scopeSpans": [{
                    "spans": [{
                        "attributes": [
                            {"key": "gen_ai.request.model", "value": {"stringValue": "model-1"}},
                            {"key": "gen_ai.input.messages", "value": {"stringValue": "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\"hello\"}]}]"}},
                            {"key": "gen_ai.output.messages", "value": {"stringValue": "[{\"role\":\"assistant\",\"parts\":[{\"type\":\"tool_call\",\"id\":\"call-1\",\"name\":\"lookup\",\"arguments\":{}}]}]"}}
                        ]
                    }]
                }]
            }]
        });

        assert_eq!(
            trace_facts(&serde_json::to_vec(&trace).unwrap()).unwrap(),
            ("model-1".to_owned(), 1, true)
        );
    }

    #[test]
    fn collection_trace_without_tool_parts_is_not_labeled_as_tool_use() {
        let trace = serde_json::json!({
            "resourceSpans": [{
                "scopeSpans": [{
                    "spans": [{
                        "attributes": [
                            {"key": "gen_ai.request.model", "value": {"stringValue": "model-1"}},
                            {"key": "gen_ai.input.messages", "value": {"stringValue": "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\"hello\"}]}]"}},
                            {"key": "gen_ai.output.messages", "value": {"stringValue": "[{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"content\":\"hi\"}]}]"}}
                        ]
                    }]
                }]
            }]
        });

        assert_eq!(
            trace_facts(&serde_json::to_vec(&trace).unwrap()).unwrap(),
            ("model-1".to_owned(), 1, false)
        );
    }

    #[test]
    fn generated_metadata_is_limited_to_the_public_taxonomy() {
        assert!(
            validate_generated_metadata(&GeneratedMetadata {
                title: "Tool-call trace".to_owned(),
                tags: vec!["tool-call".to_owned(), "agent".to_owned()],
            })
            .is_ok()
        );
        assert!(
            validate_generated_metadata(&GeneratedMetadata {
                title: "Trace".to_owned(),
                tags: vec!["invented-tag".to_owned()],
            })
            .is_err()
        );
        assert!(
            validate_generated_metadata(&GeneratedMetadata {
                title: "Trace".to_owned(),
                tags: vec!["agent".to_owned(), "agent".to_owned()],
            })
            .is_err()
        );
    }

    #[test]
    fn metadata_costing_uses_configured_token_rates_and_utc_weeks() {
        let service = MetadataService {
            api_key: None,
            model: METADATA_MODEL.to_owned(),
            weekly_budget_nanousd: 10_000_000_000,
            input_nanousd_per_token: 200,
            cached_input_nanousd_per_token: 20,
            cache_write_nanousd_per_token: 250,
            output_nanousd_per_token: 1_200,
        };
        assert_eq!(
            service
                .estimated_cost_nanousd(&ChatUsage {
                    prompt_tokens: 2_000,
                    prompt_tokens_details: ChatPromptTokenDetails {
                        cached_tokens: 1_000,
                        cache_write_tokens: 100,
                    },
                    completion_tokens: 100,
                })
                .unwrap(),
            345_000
        );
        assert_eq!(weekly_period_start(SECS_PER_WEEK + 42), SECS_PER_WEEK);
        assert_eq!(service.max_request_nanousd(), 6_707_200);
    }

    #[tokio::test]
    async fn invalid_archive_is_rejected_with_stable_code_and_purged() {
        let (state, storage) = test_state().await;
        let bytes = b"not a ZIP archive".to_vec();
        let sha256 = sha256_hex(&bytes);
        queued_job(&state, &bytes, &sha256).await;
        storage.object_bytes("intake-key", bytes);
        let (job, claim) = claim_next_job(&state).await.unwrap().unwrap();
        process_claim(&state, job, claim).await;
        let row: (String, Option<String>, Option<i64>) = sqlx::query_as(
            "SELECT state, failure_code, private_purged_at
             FROM publish_jobs WHERE id = 'job-1'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(row.0, "rejected");
        assert_eq!(row.1.as_deref(), Some("archive_invalid"));
        assert!(row.2.is_some());
        assert!(!storage.bodies.lock().unwrap().contains_key("intake-key"));
    }

    #[tokio::test]
    async fn downloaded_bytes_must_match_the_declared_sha256() {
        let (state, storage) = test_state().await;
        let bytes = b"same length".to_vec();
        queued_job(&state, &bytes, &"0".repeat(64)).await;
        storage.object_bytes("intake-key", bytes);
        let (job, claim) = claim_next_job(&state).await.unwrap().unwrap();
        process_claim(&state, job, claim).await;
        let row: (String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT state, failure_code, actual_sha256
             FROM publish_jobs WHERE id = 'job-1'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(row.0, "rejected");
        assert_eq!(row.1.as_deref(), Some("object_sha256_mismatch"));
        assert_eq!(row.2.as_deref(), Some(sha256_hex(b"same length").as_str()));
    }

    #[tokio::test]
    async fn admission_writes_one_immutable_public_pair() {
        let (state, storage) = test_state().await;
        let bytes = b"archive".to_vec();
        let sha256 = sha256_hex(&bytes);
        queued_job(&state, &bytes, &sha256).await;
        storage.object_bytes("intake-key", bytes);
        let (job, claim) = claim_next_job(&state).await.unwrap().unwrap();
        admit_claim(
            &state,
            &job,
            &claim,
            7,
            &sha256,
            AdmittedArtifacts {
                trace: b"{\"trace\":1}\n".to_vec(),
                stamp: b"{\"stamp\":1}\n".to_vec(),
            },
        )
        .await
        .unwrap();
        assert!(
            admit_claim(
                &state,
                &job,
                &claim,
                7,
                &sha256,
                AdmittedArtifacts {
                    trace: b"different".to_vec(),
                    stamp: b"different".to_vec(),
                },
            )
            .await
            .is_err()
        );
        let row: (String, String, String) = sqlx::query_as(
            "SELECT state, public_trace_object_key, public_stamp_object_key
             FROM publish_jobs WHERE id = 'job-1'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(row.0, "admitted");
        assert_eq!(
            storage.bodies.lock().unwrap().get(&row.1).unwrap(),
            b"{\"trace\":1}\n"
        );
        assert_eq!(
            storage.bodies.lock().unwrap().get(&row.2).unwrap(),
            b"{\"stamp\":1}\n"
        );
        let public = load_public_artifact(&state, "job-1").await.unwrap();
        assert_eq!(public.id, "job-1");
        assert_eq!(public.public_trace_object_key, row.1);
        assert_eq!(
            load_public_bytes(
                &state,
                &public.public_trace_object_key,
                public.public_trace_size_bytes,
                &public.public_trace_sha256,
            )
            .await
            .unwrap(),
            b"{\"trace\":1}\n"
        );
        assert_eq!(storage.bodies.lock().unwrap().len(), 2);
        storage
            .bodies
            .lock()
            .unwrap()
            .insert(row.1.clone(), b"tampered\n".to_vec());
        assert!(
            load_public_bytes(
                &state,
                &public.public_trace_object_key,
                public.public_trace_size_bytes,
                &public.public_trace_sha256,
            )
            .await
            .is_err()
        );
        assert!(load_public_artifact(&state, "job-1").await.is_ok());
        let directory = platform_directory(State(state)).await.unwrap().0;
        assert_eq!(directory.format, "llm-notary/platform-directory/v1");
        assert!(directory.key_id.starts_with("sha256:"));
    }
}
