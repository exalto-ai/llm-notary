use std::net::SocketAddr;

#[cfg(test)]
use std::sync::Arc;

use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::FromRow;
use time::Duration as CookieDuration;
#[cfg(test)]
use tokio::sync::Semaphore;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use notary_core::{
    pagination::{CursorScope, Page, PageQuery, decode_cursor},
    sha256_hex,
};

use crate::{
    ApiError, ApiResult, NotaryApiState, database_error, pagination,
    traces::owner::{MAX_TRACE_PASSWORD_BYTES, run_password_work},
    unix_timestamp,
};

#[cfg(test)]
use crate::traces::owner::TraceService;

const MAX_PUBLIC_CONTENT_MESSAGES: usize = 512;
const TRACE_ACCESS_COOKIE: &str = "notary_trace_access";
const TRACE_ACCESS_COOKIE_TTL_SECS: i64 = 24 * 60 * 60;
const TRACE_ACCESS_COOKIE_PURPOSE: &[u8] = b"notary/trace-access-cookie/v1";
const DUMMY_TRACE_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$yJIR0lVleM2KSPdVmBvsQ9uhA06YIR8aPCbRDbNvXXQ";
const MAX_REPORT_MESSAGE_CHARS: usize = 500;
const TRACE_RATE_LIMIT_KEY_PURPOSE: &[u8] = b"notary/public-trace-rate-limit/v1";
const RATE_LIMIT_RETENTION_SECS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy)]
struct TraceRateLimit {
    action: &'static str,
    max_requests: i64,
    window_secs: i64,
    error_code: &'static str,
    error_message: &'static str,
}

const TRACE_ACCESS_RATE_LIMIT: TraceRateLimit = TraceRateLimit {
    action: "password",
    max_requests: 10,
    window_secs: 60,
    error_code: "trace_access_rate_limited",
    error_message: "Too many password attempts were made from this network",
};

const TRACE_ACCESS_NETWORK_RATE_LIMIT: TraceRateLimit = TraceRateLimit {
    action: "password",
    max_requests: 60,
    window_secs: 60,
    error_code: "trace_access_rate_limited",
    error_message: "Too many password attempts were made from this network",
};
const TRACE_ACCESS_NETWORK_SCOPE: &str = "__network__";

const TRACE_REPORT_RATE_LIMIT: TraceRateLimit = TraceRateLimit {
    action: "report",
    max_requests: 5,
    window_secs: 60 * 60,
    error_code: "trace_report_rate_limited",
    error_message: "Too many reports were submitted from this network",
};

#[derive(FromRow)]
struct PublicTraceRow {
    id: String,
    visibility: String,
    access_expires_at: Option<i64>,
    access_password_hash: Option<String>,
    publisher: String,
    verified_at: i64,
    provider: String,
    provider_host: String,
    model: String,
    authenticated_provider_connection_unix_ms: Option<i64>,
    input_preview: Option<String>,
    verified_notary_key_id: Option<String>,
    verified_registry_generation: Option<i64>,
    verified_trust_source: Option<String>,
    content_object_key: String,
    content_size_bytes: i64,
    content_sha256: String,
    package_object_key: Option<String>,
    package_size_bytes: Option<i64>,
    package_sha256: Option<String>,
    disclosure_safety_version: Option<String>,
    disclosure_safety_override: bool,
}

fn public_package_metadata(trace: &PublicTraceRow) -> ApiResult<(&str, i64, &str, &str)> {
    match (
        trace.package_object_key.as_deref(),
        trace.package_size_bytes,
        trace.package_sha256.as_deref(),
        trace.disclosure_safety_version.as_deref(),
    ) {
        (Some(key), Some(size), Some(sha256), Some(safety_version)) if size > 0 => {
            Ok((key, size, sha256, safety_version))
        }
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "shared Trace {} is missing retained package metadata",
            trace.id
        ))),
    }
}

#[derive(FromRow)]
struct ListedTraceRow {
    id: String,
    publisher: String,
    provider: String,
    model: String,
    authenticated_provider_connection_unix_ms: Option<i64>,
    input_preview: Option<String>,
    output_preview: Option<String>,
    password_protected: bool,
    shared_at: i64,
    sort_at: i64,
}

#[derive(Deserialize, ToSchema)]
struct PublicTracesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    search: Option<String>,
    provider: Option<String>,
    shared_after: Option<i64>,
}

#[derive(Deserialize, Serialize)]
struct PublicTracePagePosition {
    sort_at: i64,
    id: String,
}

#[derive(Serialize, ToSchema)]
struct PublicTraceSummary {
    trace_id: String,
    title: Option<String>,
    provider: String,
    model: String,
    publisher: String,
    shared_at: Option<i64>,
    authenticated_at_unix_ms: Option<i64>,
    input_preview: Option<String>,
    output_preview: Option<String>,
    password_protected: bool,
    public_url: String,
}

#[derive(Serialize, ToSchema)]
struct PublicTraceDetail {
    trace_id: String,
    title: Option<String>,
    visibility: String,
    password_protected: bool,
    expires_at: Option<i64>,
    publisher: String,
    shared_at: i64,
    authenticated_at_unix_ms: Option<i64>,
    provider: String,
    host: String,
    model: String,
    notarized_state: &'static str,
    hosted_verification: &'static str,
    notary_key_id: Option<String>,
    notary_name: Option<String>,
    notary_operator: Option<String>,
    registry_generation: Option<i64>,
    trust_source: Option<String>,
    content_sha256: String,
    package_size_bytes: i64,
    package_sha256: String,
    disclosure_safety_version: String,
    disclosure_safety_override: bool,
    trace_url: String,
    package_url: String,
    public_url: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PublicTraceAccessRequest {
    #[schema(min_length = 1, max_length = 128)]
    password: String,
}

#[derive(Serialize, ToSchema)]
struct PublicTraceContent {
    trace_id: String,
    input_messages: Vec<serde_json::Value>,
    output_messages: Vec<serde_json::Value>,
}

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum TraceReportReason {
    SensitiveInformation,
    Harassment,
    IllegalContent,
    Spam,
    Other,
}

impl TraceReportReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::SensitiveInformation => "sensitive_information",
            Self::Harassment => "harassment",
            Self::IllegalContent => "illegal_content",
            Self::Spam => "spam",
            Self::Other => "other",
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateTraceReport {
    reason: TraceReportReason,
    #[schema(max_length = 500)]
    message: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct TraceReportReceipt {
    received: bool,
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_public_traces))
        .routes(routes!(public_trace_detail))
        .routes(routes!(access_public_trace))
        .routes(routes!(public_trace_content))
        .routes(routes!(public_trace_otlp))
        .routes(routes!(public_trace_package))
        .routes(routes!(create_trace_report))
}

#[utoipa::path(
    get,
    path = "/api/public/traces",
    summary = "List Listed verified-session traces",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query), ("search" = Option<String>, Query), ("provider" = Option<String>, Query), ("shared_after" = Option<i64>, Query, description = "Include traces shared at or after this Unix timestamp")),
    responses(
        (status = 200, body = Page<PublicTraceSummary>),
        (status = 400, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn list_public_traces(
    State(state): State<NotaryApiState>,
    query: Result<Query<PublicTracesQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<PublicTraceSummary>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let search = normalize_trace_search(query.search)?;
    let search_pattern = search.as_deref().map(public_trace_search_regex);
    let provider = normalize_trace_filter(query.provider, 100, "provider is too long")?;
    let shared_after = match query.shared_after {
        Some(value) if value < 0 => {
            return Err(ApiError::bad_request("shared_after must not be negative"));
        }
        value => value,
    };
    let page_query = PageQuery {
        limit: query.limit,
        cursor: query.cursor,
    };
    let limit = page_query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new(
        "/api/public/traces",
        &(&search, &provider, shared_after),
        "public_sort_at desc, trace_id desc",
    )
    .map_err(pagination::api_error)?;
    let position = page_query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<PublicTracePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let rows: Vec<ListedTraceRow> = sqlx::query_as(
        "SELECT traces.trace_id AS id, accounts.display_name AS publisher, traces.provider,
                traces.model,
                traces.authenticated_provider_connection_unix_ms,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.input_preview END AS input_preview,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.output_preview END AS output_preview,
                traces.access_password_hash IS NOT NULL AS password_protected,
                traces.verified_at AS shared_at,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.verified_at ELSE 0 END AS sort_at
         FROM traces
         JOIN accounts ON accounts.account_id = traces.account_id
         WHERE traces.status = 'shared'
           AND traces.visibility = 'listed'
           AND (traces.access_expires_at IS NULL OR traces.access_expires_at > $6)
           AND traces.content_object_key IS NOT NULL
           AND traces.package_object_key IS NOT NULL
           AND ($1::TEXT IS NULL OR (
                traces.access_password_hash IS NULL AND traces.provider = $1
           ))
           AND ($2::TEXT IS NULL OR (
                traces.access_password_hash IS NULL
                AND traces.listing_search_text ~* $2
           ) OR (
                traces.access_password_hash IS NOT NULL
                AND 'shared trace notary by exalto' ~* $2
           ))
           AND ($3::BIGINT IS NULL OR (
                traces.access_password_hash IS NULL AND traces.verified_at >= $3
           ))
           AND ($4::TEXT IS NULL OR (
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.verified_at ELSE 0 END,
                traces.trace_id
           ) < ($5, $4))
         ORDER BY CASE WHEN traces.access_password_hash IS NULL
                       THEN traces.verified_at ELSE 0 END DESC,
                  traces.trace_id DESC
         LIMIT $7",
    )
    .bind(&provider)
    .bind(&search_pattern)
    .bind(shared_after)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(position.as_ref().map(|position| position.sort_at))
    .bind(unix_timestamp()?)
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(error.into()))?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    let page = Page::from_limit_plus_one(rows, limit, &scope, |trace| PublicTracePagePosition {
        sort_at: trace.sort_at,
        id: trace.id.clone(),
    })
    .map_err(pagination::api_error)?;
    let items = page
        .items
        .into_iter()
        .map(|trace| {
            let protected = trace.password_protected;
            PublicTraceSummary {
                public_url: canonical_public_trace_url(&state, &trace.id),
                trace_id: trace.id,
                title: (!protected).then(|| trace.input_preview.clone()).flatten(),
                provider: if protected {
                    "protected".to_owned()
                } else {
                    trace.provider
                },
                model: if protected {
                    "Shared trace".to_owned()
                } else {
                    trace.model
                },
                publisher: if protected {
                    "Notary by Exalto".to_owned()
                } else {
                    trace.publisher
                },
                shared_at: (!protected).then_some(trace.shared_at),
                authenticated_at_unix_ms: (!protected)
                    .then_some(trace.authenticated_provider_connection_unix_ms)
                    .flatten(),
                input_preview: (!protected).then_some(trace.input_preview).flatten(),
                output_preview: (!protected).then_some(trace.output_preview).flatten(),
                password_protected: protected,
            }
        })
        .collect();
    Ok(Json(Page {
        items,
        next_cursor: page.next_cursor,
    }))
}

fn normalize_trace_filter(
    value: Option<String>,
    maximum: usize,
    error: &'static str,
) -> ApiResult<Option<String>> {
    let value = value.map(|value| value.trim().to_lowercase());
    match value {
        Some(value) if value.len() > maximum => Err(ApiError::bad_request(error)),
        Some(value) if value.is_empty() => Ok(None),
        value => Ok(value),
    }
}

fn normalize_trace_search(value: Option<String>) -> ApiResult<Option<String>> {
    let value = normalize_trace_filter(value, 200, "search is too long")?;
    match value {
        Some(value) if !has_indexable_search_trigram(&value) => Err(ApiError::bad_request(
            "search must include 3 consecutive letters or numbers",
        )),
        value => Ok(value),
    }
}

fn has_indexable_search_trigram(value: &str) -> bool {
    let mut run = 0;
    for character in value.chars() {
        if character.is_alphanumeric() {
            run += 1;
            if run == 3 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn public_trace_search_regex(value: &str) -> String {
    let mut pattern = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern
}

#[utoipa::path(
    get,
    path = "/api/public/traces/{trace_id}",
    summary = "Get one admitted public Trace",
    params(("trace_id" = String, Path)),
    responses(
        (status = 200, body = PublicTraceDetail),
        (status = 404, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn public_trace_detail(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<Response> {
    let trace = load_public_trace(&state, &jar, &trace_id).await?;
    let notary = trace.verified_notary_key_id.as_ref().and_then(|key_id| {
        state
            .registry
            .notaries
            .iter()
            .find(|record| &record.key_id == key_id)
    });
    let notary_name = notary.map(|record| record.name.clone());
    let notary_operator = notary.map(|record| record.operator.clone());
    let (package_size_bytes, package_sha256, safety_version) = {
        let (_, size, sha256, safety_version) = public_package_metadata(&trace)?;
        (size, sha256.to_owned(), safety_version.to_owned())
    };
    let detail = PublicTraceDetail {
        trace_id: trace.id.clone(),
        title: trace.input_preview.clone(),
        visibility: trace.visibility.clone(),
        password_protected: trace.access_password_hash.is_some(),
        expires_at: trace.access_expires_at,
        publisher: trace.publisher,
        shared_at: trace.verified_at,
        authenticated_at_unix_ms: trace.authenticated_provider_connection_unix_ms,
        provider: trace.provider,
        host: trace.provider_host,
        model: trace.model,
        notarized_state: "notarized",
        hosted_verification: "passed",
        notary_key_id: trace.verified_notary_key_id,
        notary_name,
        notary_operator,
        registry_generation: trace.verified_registry_generation,
        trust_source: trace.verified_trust_source,
        content_sha256: trace.content_sha256,
        package_size_bytes,
        package_sha256,
        disclosure_safety_version: safety_version,
        disclosure_safety_override: trace.disclosure_safety_override,
        trace_url: format!("/api/public/traces/{}/trace.otlp.json", trace.id),
        package_url: format!("/api/public/traces/{}/package.llmtrace", trace.id),
        public_url: canonical_public_trace_url(&state, &trace.id),
    };
    let mut response = Json(detail).into_response();
    add_discovery_headers(&mut response, &trace.visibility);
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/public/traces/{trace_id}/access",
    summary = "Establish narrowly scoped access to a protected public Trace",
    params(("trace_id" = String, Path)),
    request_body = PublicTraceAccessRequest,
    responses(
        (status = 204, description = "Access established"),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn access_public_trace(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(trace_id): Path<String>,
    Json(request): Json<PublicTraceAccessRequest>,
) -> ApiResult<(CookieJar, StatusCode)> {
    if request.password.is_empty() || request.password.len() > MAX_TRACE_PASSWORD_BYTES {
        return Err(trace_unavailable());
    }
    let now = unix_timestamp()?;
    enforce_trace_request_limit(
        &state,
        &headers,
        peer,
        TRACE_ACCESS_NETWORK_SCOPE,
        now,
        TRACE_ACCESS_NETWORK_RATE_LIMIT,
    )
    .await?;
    enforce_trace_request_limit(
        &state,
        &headers,
        peer,
        &trace_id,
        now,
        TRACE_ACCESS_RATE_LIMIT,
    )
    .await?;
    let trace = load_public_trace_optional(&state, &trace_id).await?;
    let password_hash = trace
        .as_ref()
        .and_then(|trace| trace.access_password_hash.as_deref())
        .unwrap_or(DUMMY_TRACE_PASSWORD_HASH);
    let valid =
        verify_trace_password(request.password.into_bytes(), password_hash.to_owned()).await?;
    let Some(trace) = trace else {
        return Err(trace_unavailable());
    };
    if trace.access_password_hash.is_some() && !valid {
        return Err(trace_unavailable());
    }
    public_package_metadata(&trace)?;
    let cookie = trace_access_cookie(&state, &trace, now)?;
    Ok((jar.add(cookie), StatusCode::NO_CONTENT))
}

#[utoipa::path(
    get,
    path = "/api/public/traces/{trace_id}/content",
    summary = "Get the bounded disclosed conversation from one public Trace",
    params(("trace_id" = String, Path)),
    responses(
        (status = 200, body = PublicTraceContent),
        (status = 404, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn public_trace_content(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<Json<PublicTraceContent>> {
    let trace = load_public_trace(&state, &jar, &trace_id).await?;
    let bytes = load_public_bytes(
        &state,
        &trace.content_object_key,
        trace.content_size_bytes,
        &trace.content_sha256,
    )
    .await?;
    let (input_messages, output_messages) = disclosed_messages(&bytes)?;
    Ok(Json(PublicTraceContent {
        trace_id: trace.id,
        input_messages,
        output_messages,
    }))
}

#[utoipa::path(
    get,
    path = "/api/public/traces/{trace_id}/trace.otlp.json",
    summary = "Download the verified canonical OpenTelemetry trace",
    params(("trace_id" = String, Path)),
    responses(
        (status = 200, body = serde_json::Value, content_type = "application/json"),
        (status = 404, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn public_trace_otlp(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<Response> {
    let trace = load_public_trace(&state, &jar, &trace_id).await?;
    let bytes = load_public_bytes(
        &state,
        &trace.content_object_key,
        trace.content_size_bytes,
        &trace.content_sha256,
    )
    .await?;
    Ok(public_bytes(
        bytes,
        "application/json; charset=utf-8",
        &trace.content_sha256,
        None,
        &trace.visibility,
    ))
}

#[utoipa::path(
    get,
    path = "/api/public/traces/{trace_id}/package.llmtrace",
    summary = "Download the exact verified portable proof package",
    params(("trace_id" = String, Path)),
    responses(
        (status = 200, body = Vec<u8>, content_type = "application/vnd.exalto.notary.trace-package+zip"),
        (status = 404, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn public_trace_package(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<Response> {
    let trace = load_public_trace(&state, &jar, &trace_id).await?;
    let (object_key, size_bytes, sha256, _) = public_package_metadata(&trace)?;
    let bytes = load_public_bytes(&state, object_key, size_bytes, sha256).await?;
    Ok(public_bytes(
        bytes,
        super::storage::ARCHIVE_CONTENT_TYPE,
        sha256,
        Some(&format!("{trace_id}.llmtrace")),
        &trace.visibility,
    ))
}

#[utoipa::path(
    post,
    path = "/api/public/traces/{trace_id}/reports",
    summary = "Report a public Trace",
    params(("trace_id" = String, Path)),
    request_body = CreateTraceReport,
    responses(
        (status = 200, body = TraceReportReceipt),
        (status = 400, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "public-traces"
)]
async fn create_trace_report(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(trace_id): Path<String>,
    Json(request): Json<CreateTraceReport>,
) -> ApiResult<Json<TraceReportReceipt>> {
    let trace = load_public_trace(&state, &jar, &trace_id).await?;
    let message = normalize_report_message(request.message)?;
    let now = unix_timestamp()?;
    enforce_trace_request_limit(
        &state,
        &headers,
        peer,
        &trace.id,
        now,
        TRACE_REPORT_RATE_LIMIT,
    )
    .await?;
    sqlx::query(
        "INSERT INTO trace_reports
             (report_id, trace_id, reason, message, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(trace.id)
    .bind(request.reason.as_str())
    .bind(message)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(Json(TraceReportReceipt { received: true }))
}

async fn load_public_trace(
    state: &NotaryApiState,
    jar: &CookieJar,
    trace_id: &str,
) -> ApiResult<PublicTraceRow> {
    let trace = load_public_trace_optional(state, trace_id)
        .await?
        .ok_or_else(trace_unavailable)?;
    require_trace_access(state, jar, &trace)?;
    public_package_metadata(&trace)?;
    Ok(trace)
}

async fn load_public_trace_optional(
    state: &NotaryApiState,
    trace_id: &str,
) -> ApiResult<Option<PublicTraceRow>> {
    let now = unix_timestamp()?;
    sqlx::query_as(
        "SELECT traces.trace_id AS id, traces.visibility,
                traces.access_expires_at, traces.access_password_hash,
                accounts.display_name AS publisher,
                traces.verified_at, traces.provider,
                traces.provider_host, traces.model,
                traces.authenticated_provider_connection_unix_ms,
                traces.input_preview,
                traces.verified_notary_key_id,
                traces.verified_registry_generation,
                traces.verified_trust_source,
                traces.content_object_key,
                traces.content_size_bytes,
                traces.content_sha256,
                traces.package_object_key, traces.package_size_bytes,
                traces.package_sha256,
                traces.disclosure_safety_version,
                traces.disclosure_safety_override
         FROM traces
         JOIN accounts ON accounts.account_id = traces.account_id
         WHERE traces.trace_id = $1 AND traces.status = 'shared'
           AND (traces.access_expires_at IS NULL OR traces.access_expires_at > $2)
           AND traces.content_object_key IS NOT NULL",
    )
    .bind(trace_id)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)
}

fn require_trace_access(
    state: &NotaryApiState,
    jar: &CookieJar,
    trace: &PublicTraceRow,
) -> ApiResult<()> {
    let Some(password_hash) = trace.access_password_hash.as_deref() else {
        return Ok(());
    };
    let now = unix_timestamp()?;
    let token = jar
        .get(TRACE_ACCESS_COOKIE)
        .map(Cookie::value)
        .ok_or_else(trace_unavailable)?;
    verify_trace_access_token(state, &trace.id, password_hash, token, now)
        .then_some(())
        .ok_or_else(trace_unavailable)
}

async fn verify_trace_password(password: Vec<u8>, password_hash: String) -> ApiResult<bool> {
    run_password_work(move || {
        PasswordHash::new(&password_hash)
            .ok()
            .is_some_and(|parsed| {
                Argon2::default()
                    .verify_password(&password, &parsed)
                    .is_ok()
            })
    })
    .await
}

fn trace_access_cookie(
    state: &NotaryApiState,
    trace: &PublicTraceRow,
    now: i64,
) -> ApiResult<Cookie<'static>> {
    let expires_at = trace
        .access_expires_at
        .unwrap_or(now + TRACE_ACCESS_COOKIE_TTL_SECS)
        .min(now + TRACE_ACCESS_COOKIE_TTL_SECS);
    let password_hash = trace.access_password_hash.as_deref().unwrap_or("");
    let signature = trace_access_signature(state, &trace.id, password_hash, expires_at)?;
    let token = format!("{expires_at}.{}", URL_SAFE_NO_PAD.encode(signature));
    Ok(Cookie::build((TRACE_ACCESS_COOKIE, token))
        .path(format!("/api/public/traces/{}", trace.id))
        .http_only(true)
        .secure(state.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(expires_at.saturating_sub(now)))
        .build())
}

fn verify_trace_access_token(
    state: &NotaryApiState,
    trace_id: &str,
    password_hash: &str,
    token: &str,
    now: i64,
) -> bool {
    let Some((expires_at, signature)) = token.split_once('.') else {
        return false;
    };
    let Ok(expires_at) = expires_at.parse::<i64>() else {
        return false;
    };
    if expires_at <= now || expires_at > now + TRACE_ACCESS_COOKIE_TTL_SECS {
        return false;
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    trace_access_verifier(state, trace_id, password_hash, expires_at)
        .is_ok_and(|verifier| verifier.verify_slice(&signature).is_ok())
}

fn trace_access_signature(
    state: &NotaryApiState,
    trace_id: &str,
    password_hash: &str,
    expires_at: i64,
) -> ApiResult<Vec<u8>> {
    Ok(
        trace_access_verifier(state, trace_id, password_hash, expires_at)?
            .finalize()
            .into_bytes()
            .to_vec(),
    )
}

fn trace_access_verifier(
    state: &NotaryApiState,
    trace_id: &str,
    password_hash: &str,
    expires_at: i64,
) -> ApiResult<Hmac<Sha256>> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(&state.admission.anonymous_subject_hmac_key)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid anonymous subject key")))?;
    let expires_at = expires_at.to_string();
    for value in [
        TRACE_ACCESS_COOKIE_PURPOSE,
        trace_id.as_bytes(),
        password_hash.as_bytes(),
        expires_at.as_bytes(),
    ] {
        hmac.update(&(value.len() as u64).to_be_bytes());
        hmac.update(value);
    }
    Ok(hmac)
}

fn trace_unavailable() -> ApiError {
    ApiError::not_found("public Trace is unavailable")
}

fn disclosed_messages(trace: &[u8]) -> ApiResult<(Vec<serde_json::Value>, Vec<serde_json::Value>)> {
    let trace: serde_json::Value = serde_json::from_slice(trace)
        .map_err(|error| ApiError::internal(anyhow::anyhow!(error)))?;
    Ok((
        trace_messages(&trace, "gen_ai.input.messages"),
        trace_messages(&trace, "gen_ai.output.messages"),
    ))
}

fn trace_messages(trace: &serde_json::Value, attribute_key: &str) -> Vec<serde_json::Value> {
    let Some(resources) = trace
        .get("resourceSpans")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    resources
        .iter()
        .filter_map(|resource| {
            resource
                .get("scopeSpans")
                .and_then(serde_json::Value::as_array)
        })
        .flatten()
        .filter_map(|scope| scope.get("spans").and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(|span| span.get("attributes").and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(|attribute| {
            (attribute.get("key").and_then(serde_json::Value::as_str) == Some(attribute_key))
                .then(|| attribute.pointer("/value/stringValue"))
                .flatten()
                .and_then(serde_json::Value::as_str)
                .and_then(|messages| serde_json::from_str::<Vec<serde_json::Value>>(messages).ok())
        })
        .flatten()
        .take(MAX_PUBLIC_CONTENT_MESSAGES)
        .collect()
}

async fn enforce_trace_request_limit(
    state: &NotaryApiState,
    headers: &HeaderMap,
    peer: SocketAddr,
    trace_id: &str,
    now: i64,
    rate_limit: TraceRateLimit,
) -> ApiResult<()> {
    let subject_key = trace_rate_limit_subject_key(state, headers, peer, rate_limit.action)?;
    let window_reset_before = now - rate_limit.window_secs;
    let request_count = sqlx::query_scalar::<_, i64>(
        "INSERT INTO public_trace_rate_limits
             (trace_id, subject_key_sha256, action, window_started_at, request_count, updated_at)
         VALUES ($1, $2, $3, $4, 1, $4)
         ON CONFLICT (trace_id, subject_key_sha256, action) DO UPDATE
         SET window_started_at = CASE
                 WHEN public_trace_rate_limits.window_started_at <= $5 THEN $4
                 ELSE public_trace_rate_limits.window_started_at
             END,
             request_count = CASE
                 WHEN public_trace_rate_limits.window_started_at <= $5 THEN 1
                 ELSE public_trace_rate_limits.request_count + 1
             END,
             updated_at = $4
         WHERE public_trace_rate_limits.window_started_at <= $5
            OR public_trace_rate_limits.request_count < $6
         RETURNING request_count",
    )
    .bind(trace_id)
    .bind(subject_key)
    .bind(rate_limit.action)
    .bind(now)
    .bind(window_reset_before)
    .bind(rate_limit.max_requests)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    if request_count.is_none() {
        return Err(ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            rate_limit.error_code,
            rate_limit.error_message,
        ));
    }
    Ok(())
}

pub(super) async fn purge_expired_trace_rate_limits(state: &NotaryApiState) -> Result<()> {
    let cutoff = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?
        - RATE_LIMIT_RETENTION_SECS;
    sqlx::query("DELETE FROM public_trace_rate_limits WHERE updated_at < $1")
        .bind(cutoff)
        .execute(&state.database)
        .await?;
    sqlx::query("DELETE FROM trace_access_change_limits WHERE updated_at < $1")
        .bind(cutoff)
        .execute(&state.database)
        .await?;
    Ok(())
}

fn trace_rate_limit_subject_key(
    state: &NotaryApiState,
    headers: &HeaderMap,
    peer: SocketAddr,
    action: &str,
) -> ApiResult<String> {
    let client_ip = crate::admissions::resolve_client_ip(headers, Some(peer), &state.admission)?;
    let client = crate::admissions::normalized_client_address(client_ip);
    let version = state.admission.anonymous_subject_key_version.to_string();
    let mut hmac = Hmac::<Sha256>::new_from_slice(&state.admission.anonymous_subject_hmac_key)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid anonymous subject key")))?;
    for value in [
        TRACE_RATE_LIMIT_KEY_PURPOSE,
        version.as_bytes(),
        action.as_bytes(),
        client.as_bytes(),
    ] {
        hmac.update(&(value.len() as u64).to_be_bytes());
        hmac.update(value);
    }
    Ok(format!(
        "v{}:{}",
        state.admission.anonymous_subject_key_version,
        hex::encode(hmac.finalize().into_bytes())
    ))
}

fn normalize_report_message(message: Option<String>) -> ApiResult<Option<String>> {
    let message = message.map(|message| message.trim().to_owned());
    match message {
        Some(message) if message.chars().count() > MAX_REPORT_MESSAGE_CHARS => Err(
            ApiError::bad_request("report message must contain at most 500 characters"),
        ),
        Some(message) if message.is_empty() => Ok(None),
        message => Ok(message),
    }
}

pub(super) async fn load_public_bytes(
    state: &NotaryApiState,
    object_key: &str,
    size_bytes: i64,
    sha256: &str,
) -> ApiResult<Vec<u8>> {
    let limit: usize = size_bytes
        .try_into()
        .map_err(|_| ApiError::service_unavailable("public artifact metadata is invalid"))?;
    let bytes = state
        .traces
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

fn canonical_public_trace_url(state: &NotaryApiState, trace_id: &str) -> String {
    state
        .public_origin
        .join(&format!("/s/{trace_id}"))
        .expect("trace path is a valid same-origin URL")
        .to_string()
}

fn add_discovery_headers(response: &mut Response, visibility: &str) {
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("cookie"));
    if visibility == "unlisted" {
        response.headers_mut().insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow, noarchive"),
        );
    }
}

pub(super) fn public_bytes(
    bytes: Vec<u8>,
    content_type: &'static str,
    sha256: &str,
    filename: Option<&str>,
    visibility: &str,
) -> Response {
    let mut response = (StatusCode::OK, Body::from(bytes)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        "x-content-sha256",
        HeaderValue::from_str(sha256).expect("SHA-256 is a valid header value"),
    );
    if let Some(filename) = filename {
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                .expect("safe trace ID makes a valid filename"),
        );
    }
    add_discovery_headers(&mut response, visibility);
    response
}

#[cfg(test)]
mod tests {
    use argon2::{PasswordHasher, password_hash::SaltString};
    use url::Url;

    use super::*;

    fn public_test_state(
        database: crate::test_database::TestDatabase,
        traces: TraceService,
    ) -> NotaryApiState {
        NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .unwrap(),
            public_origin: Url::parse("https://notary.exalto.ai").unwrap(),
            secure_cookies: true,
            registry: crate::tests::test_registry(),
            traces,
            admission: Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        }
    }

    #[test]
    fn public_trace_filters_are_normalized_and_bounded() {
        assert_eq!(
            normalize_trace_filter(Some("  OpenAI  ".to_owned()), 100, "too long").unwrap(),
            Some("openai".to_owned())
        );
        assert_eq!(
            normalize_trace_filter(Some("   ".to_owned()), 100, "too long").unwrap(),
            None
        );
        assert!(normalize_trace_filter(Some("x".repeat(101)), 100, "too long").is_err());
        assert!(normalize_trace_search(Some("ai".to_owned())).is_err());
        assert!(normalize_trace_search(Some("%%%".to_owned())).is_err());
        assert!(normalize_trace_search(Some("a-b-c".to_owned())).is_err());
        assert_eq!(
            normalize_trace_search(Some("  GPT  ".to_owned())).unwrap(),
            Some("gpt".to_owned())
        );
        assert_eq!(public_trace_search_regex("100%_safe!"), "100%_safe!");
        assert_eq!(public_trace_search_regex("a.b[c]"), "a\\.b\\[c\\]");
    }

    async fn insert_public_trace(
        pool: &sqlx::PgPool,
        id: &str,
        visibility: &str,
        provider: &str,
        shared_at: i64,
        authenticated_at: Option<i64>,
        search_text: &str,
    ) {
        sqlx::query(
            "INSERT INTO traces (
                 trace_id, account_id, source_trace_id, idempotency_key, status, package_format,
                 declared_package_size_bytes, declared_package_sha256, staging_object_key,
                 committed_staging_object_key, upload_expires_at, created_at, updated_at,
                 verified_at, admitted_package_size_bytes, admitted_package_sha256,
                 content_object_key, content_size_bytes, content_sha256,
                 visibility, package_object_key, package_size_bytes, package_sha256,
                 disclosure_safety_version, provider, provider_host, model,
                 authenticated_provider_connection_unix_ms,
                 input_preview, output_preview, listing_search_text
             ) VALUES (
                 $1, 'public-trace-user', $1 || '-source', $1 || '-key', 'shared', $2,
                 1, $3, $1 || '-upload', $1 || '-intake', 10, 1, 1,
                 $8, 1, $3, $1 || '-trace', 1, $4, $5,
                 $1 || '-package', 1, $6, 'notary/public-package-safety/v1',
                 $7, $7 || '.example.com', 'model-' || $1, $9,
                 'input ' || $1, 'output ' || $1, $10
             )",
        )
        .bind(id)
        .bind(crate::traces::storage::PACKAGE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind(visibility)
        .bind("c".repeat(64))
        .bind(provider)
        .bind(shared_at)
        .bind(authenticated_at)
        .bind(search_text)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn public_trace_collection_pages_ties_nulls_filters_and_concurrent_inserts() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "public-trace-user", 1, "publisher").await;
        insert_public_trace(
            &database.pool,
            "trace-c",
            "listed",
            "openai",
            100,
            Some(100),
            "openai publisher 100%_safe! prompt",
        )
        .await;
        insert_public_trace(
            &database.pool,
            "trace-b",
            "listed",
            "openai",
            100,
            Some(100),
            "openai publisher 100xxsafe prompt",
        )
        .await;
        insert_public_trace(
            &database.pool,
            "trace-a",
            "listed",
            "anthropic",
            90,
            Some(90),
            "anthropic publisher",
        )
        .await;
        insert_public_trace(
            &database.pool,
            "trace-null",
            "listed",
            "openai",
            80,
            None,
            "openai publisher without timestamp",
        )
        .await;
        insert_public_trace(
            &database.pool,
            "hidden",
            "unlisted",
            "openai",
            95,
            Some(95),
            "openai publisher hidden",
        )
        .await;
        let state = public_test_state(database, TraceService::disabled_for_test());

        let first = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: Some(2),
                cursor: None,
                search: None,
                provider: None,
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            first
                .items
                .iter()
                .map(|trace| trace.trace_id.as_str())
                .collect::<Vec<_>>(),
            ["trace-c", "trace-b"]
        );
        let cursor = first.next_cursor.unwrap();

        insert_public_trace(
            &state.database,
            "trace-new",
            "listed",
            "openai",
            200,
            Some(200),
            "openai publisher inserted later",
        )
        .await;
        let second = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: Some(2),
                cursor: Some(cursor),
                search: None,
                provider: None,
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            second
                .items
                .iter()
                .map(|trace| trace.trace_id.as_str())
                .collect::<Vec<_>>(),
            ["trace-a", "trace-null"]
        );
        assert!(second.next_cursor.is_none());

        let literal_search = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: Some("100%_safe!".to_owned()),
                provider: None,
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(literal_search.items.len(), 1);
        assert_eq!(literal_search.items[0].trace_id, "trace-c");

        let recent = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: None,
                shared_after: Some(150),
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(recent.items.len(), 1);
        assert_eq!(recent.items[0].trace_id, "trace-new");
        assert_eq!(recent.items[0].shared_at, Some(200));

        let provider_filter = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: Some("ANTHROPIC".to_owned()),
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(provider_filter.items.len(), 1);
        assert_eq!(provider_filter.items[0].trace_id, "trace-a");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn protected_collection_entries_do_not_disclose_trace_metadata() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "public-trace-user", 1, "publisher").await;
        insert_public_trace(
            &database.pool,
            "trace-public",
            "listed",
            "openai",
            100,
            Some(100),
            "openai public prompt",
        )
        .await;
        insert_public_trace(
            &database.pool,
            "trace-protected",
            "listed",
            "secret-provider",
            200,
            Some(200),
            "secret-provider private prompt",
        )
        .await;
        sqlx::query("UPDATE traces SET access_password_hash = $2 WHERE trace_id = $1")
            .bind("trace-protected")
            .bind(DUMMY_TRACE_PASSWORD_HASH)
            .execute(&database.pool)
            .await
            .unwrap();
        let state = public_test_state(database, TraceService::disabled_for_test());

        let page = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: None,
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        let protected = page
            .items
            .iter()
            .find(|trace| trace.trace_id == "trace-protected")
            .unwrap();
        assert_eq!(protected.provider, "protected");
        assert_eq!(protected.model, "Shared trace");
        assert_eq!(protected.publisher, "Notary by Exalto");
        assert!(protected.title.is_none());
        assert!(protected.shared_at.is_none());
        assert!(protected.authenticated_at_unix_ms.is_none());
        assert!(protected.input_preview.is_none());
        assert!(protected.output_preview.is_none());

        let filtered = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: Some("secret-provider".to_owned()),
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert!(filtered.items.is_empty());

        let searched = list_public_traces(
            State(state.clone()),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: Some("private prompt".to_owned()),
                provider: None,
                shared_after: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert!(searched.items.is_empty());

        let recent = list_public_traces(
            State(state),
            Ok(Query(PublicTracesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: None,
                shared_after: Some(0),
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            recent
                .items
                .iter()
                .map(|trace| trace.trace_id.as_str())
                .collect::<Vec<_>>(),
            ["trace-public"]
        );
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn protected_trace_access_is_cookie_based_and_non_disclosing() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "public-trace-user", 1, "publisher").await;
        insert_public_trace(
            &database.pool,
            "trace-protected",
            "unlisted",
            "openai",
            100,
            Some(100),
            "openai private prompt",
        )
        .await;
        let salt = SaltString::encode_b64(b"deterministic-salt").unwrap();
        let password_hash = Argon2::default()
            .hash_password(b"correct-password", &salt)
            .unwrap()
            .to_string();
        sqlx::query("UPDATE traces SET access_password_hash = $2 WHERE trace_id = $1")
            .bind("trace-protected")
            .bind(password_hash)
            .execute(&database.pool)
            .await
            .unwrap();
        let state = public_test_state(database, TraceService::disabled_for_test());
        let peer = ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41_000)));

        let wrong_password = access_public_trace(
            State(state.clone()),
            peer,
            HeaderMap::new(),
            CookieJar::new(),
            Path("trace-protected".to_owned()),
            Json(PublicTraceAccessRequest {
                password: "wrong-password".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        let missing = access_public_trace(
            State(state.clone()),
            peer,
            HeaderMap::new(),
            CookieJar::new(),
            Path("trace-missing".to_owned()),
            Json(PublicTraceAccessRequest {
                password: "wrong-password".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (
                wrong_password.status,
                wrong_password.code,
                wrong_password.message
            ),
            (missing.status, missing.code, missing.message)
        );

        let (jar, status) = access_public_trace(
            State(state.clone()),
            peer,
            HeaderMap::new(),
            CookieJar::new(),
            Path("trace-protected".to_owned()),
            Json(PublicTraceAccessRequest {
                password: "correct-password".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(jar.get(TRACE_ACCESS_COOKIE).is_some());
        public_trace_detail(
            State(state.clone()),
            jar,
            Path("trace-protected".to_owned()),
        )
        .await
        .expect("scoped cookie unlocks the Trace");

        sqlx::query("UPDATE traces SET status = 'stopped' WHERE trace_id = $1")
            .bind("trace-protected")
            .execute(&state.database)
            .await
            .unwrap();
        let stopped = access_public_trace(
            State(state),
            peer,
            HeaderMap::new(),
            CookieJar::new(),
            Path("trace-protected".to_owned()),
            Json(PublicTraceAccessRequest {
                password: "correct-password".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (stopped.status, stopped.code, stopped.message),
            (missing.status, missing.code, missing.message)
        );
    }

    #[tokio::test]
    async fn trace_access_cookie_is_scoped_and_invalidated_by_trace_or_password_changes() {
        let database =
            sqlx::PgPool::connect_lazy("postgres://postgres:postgres@localhost/postgres").unwrap();
        let state = NotaryApiState {
            database,
            _test_database: None,
            http: reqwest::Client::new(),
            github_client_id: String::new(),
            github_client_secret: String::new(),
            github_callback_url: Url::parse("https://example.test/auth/github").unwrap(),
            google_client_id: String::new(),
            google_client_secret: String::new(),
            google_callback_url: Url::parse("https://example.test/auth/google").unwrap(),
            public_origin: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            registry: crate::tests::test_registry(),
            traces: TraceService::disabled_for_test(),
            admission: Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        };
        let trace = PublicTraceRow {
            id: "trc_cookie".to_owned(),
            visibility: "unlisted".to_owned(),
            access_expires_at: None,
            access_password_hash: Some("password-hash-a".to_owned()),
            publisher: "publisher".to_owned(),
            verified_at: 1,
            provider: "openai".to_owned(),
            provider_host: "api.openai.com".to_owned(),
            model: "gpt-test".to_owned(),
            authenticated_provider_connection_unix_ms: Some(1),
            input_preview: Some("preview".to_owned()),
            verified_notary_key_id: Some("key".to_owned()),
            verified_registry_generation: Some(1),
            verified_trust_source: Some("registry".to_owned()),
            content_object_key: "content".to_owned(),
            content_size_bytes: 1,
            content_sha256: "a".repeat(64),
            package_object_key: Some("package".to_owned()),
            package_size_bytes: Some(1),
            package_sha256: Some("b".repeat(64)),
            disclosure_safety_version: Some("v1".to_owned()),
            disclosure_safety_override: false,
        };
        let now = 1_000_000;
        let cookie = trace_access_cookie(&state, &trace, now).unwrap();
        assert_eq!(cookie.path(), Some("/api/public/traces/trc_cookie"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert!(cookie.domain().is_none());
        assert!(verify_trace_access_token(
            &state,
            &trace.id,
            trace.access_password_hash.as_deref().unwrap(),
            cookie.value(),
            now,
        ));
        assert!(!verify_trace_access_token(
            &state,
            "trc_other",
            trace.access_password_hash.as_deref().unwrap(),
            cookie.value(),
            now,
        ));
        assert!(!verify_trace_access_token(
            &state,
            &trace.id,
            "password-hash-b",
            cookie.value(),
            now,
        ));
        assert!(!verify_trace_access_token(
            &state,
            &trace.id,
            trace.access_password_hash.as_deref().unwrap(),
            cookie.value(),
            now + TRACE_ACCESS_COOKIE_TTL_SECS,
        ));
    }

    #[tokio::test]
    async fn unlisted_artifacts_are_noindex_and_export_exact_bytes() {
        let package = b"exact admitted package bytes".to_vec();
        let response = public_bytes(
            package.clone(),
            crate::traces::storage::ARCHIVE_CONTENT_TYPE,
            &"a".repeat(64),
            Some("trc-test.llmtrace"),
            "unlisted",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-robots-tag").unwrap(),
            "noindex, nofollow, noarchive"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"trc-test.llmtrace\""
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        let body = axum::body::to_bytes(response.into_body(), package.len())
            .await
            .unwrap();
        assert_eq!(body.as_ref(), package.as_slice());
    }

    #[test]
    fn listed_artifacts_do_not_receive_a_noindex_header() {
        let response = public_bytes(
            b"trace".to_vec(),
            "application/json; charset=utf-8",
            &"b".repeat(64),
            None,
            "listed",
        );
        assert!(!response.headers().contains_key("x-robots-tag"));
    }

    #[test]
    fn report_messages_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_report_message(Some("  concise reason  ".to_owned())).unwrap(),
            Some("concise reason".to_owned())
        );
        assert_eq!(
            normalize_report_message(Some("   ".to_owned())).unwrap(),
            None
        );
        assert!(normalize_report_message(Some("x".repeat(501))).is_err());
    }

    #[tokio::test]
    async fn trace_passwords_round_trip_and_bound_verification() {
        use argon2::{
            PasswordHasher,
            password_hash::{SaltString, rand_core::OsRng},
        };

        let password = "пароль\n🔐123";
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        assert!(
            verify_trace_password(password.as_bytes().to_vec(), hash.clone())
                .await
                .unwrap()
        );
        assert!(
            !verify_trace_password(b"wrong-password".to_vec(), hash.clone())
                .await
                .unwrap()
        );

        let capacity = Arc::new(Semaphore::new(1));
        let _held = capacity.clone().acquire_owned().await.unwrap();
        let saturated =
            crate::traces::owner::run_password_work_with_capacity(capacity, || true).await;
        assert!(matches!(
            saturated,
            Err(ApiError {
                code: "trace_password_capacity",
                ..
            })
        ));
        assert!(
            !verify_trace_password(password.as_bytes().to_vec(), "invalid-hash".to_owned())
                .await
                .unwrap()
        );
    }
}
