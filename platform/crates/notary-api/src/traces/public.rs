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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::FromRow;
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
    traces::owner::{MAX_SHARE_PASSWORD_BYTES, run_share_password_work},
    unix_timestamp,
};

const SHARE_PASSWORD_HEADER: &str = "x-share-password";
const MAX_REPORT_MESSAGE_CHARS: usize = 500;
const SHARE_RATE_LIMIT_KEY_PURPOSE: &[u8] = b"llm-notary/share-rate-limit/v1";
const RATE_LIMIT_RETENTION_SECS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy)]
struct ShareRateLimit {
    action: &'static str,
    max_requests: i64,
    window_secs: i64,
    error_code: &'static str,
    error_message: &'static str,
}

const SHARE_PASSWORD_RATE_LIMIT: ShareRateLimit = ShareRateLimit {
    action: "password",
    max_requests: 10,
    window_secs: 60,
    error_code: "share_password_rate_limited",
    error_message: "Too many password attempts were made from this network",
};

const SHARE_REPORT_RATE_LIMIT: ShareRateLimit = ShareRateLimit {
    action: "report",
    max_requests: 5,
    window_secs: 60 * 60,
    error_code: "share_report_rate_limited",
    error_message: "Too many reports were submitted from this network",
};

#[derive(FromRow)]
struct PublicShareRow {
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

fn public_package_metadata(share: &PublicShareRow) -> ApiResult<(&str, i64, &str, &str)> {
    match (
        share.package_object_key.as_deref(),
        share.package_size_bytes,
        share.package_sha256.as_deref(),
        share.disclosure_safety_version.as_deref(),
    ) {
        (Some(key), Some(size), Some(sha256), Some(safety_version)) if size > 0 => {
            Ok((key, size, sha256, safety_version))
        }
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "shared Trace {} is missing retained package metadata",
            share.id
        ))),
    }
}

#[derive(FromRow)]
struct ListedShareRow {
    id: String,
    publisher: String,
    provider: String,
    model: String,
    authenticated_provider_connection_unix_ms: Option<i64>,
    input_preview: Option<String>,
    output_preview: Option<String>,
    password_protected: bool,
    page_authenticated_at_unix_ms: i64,
}

#[derive(Deserialize, ToSchema)]
struct ListedSharesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    search: Option<String>,
    provider: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct ListedSharePagePosition {
    authenticated_at_unix_ms: i64,
    id: String,
}

#[derive(Serialize, ToSchema)]
struct ListedShareSummary {
    id: String,
    provider: String,
    model: String,
    publisher: String,
    authenticated_at_unix_ms: Option<i64>,
    input_preview: Option<String>,
    output_preview: Option<String>,
    password_protected: bool,
    share_url: String,
}

#[derive(Serialize, ToSchema)]
struct PublicShareDetail {
    id: String,
    visibility: String,
    password_protected: bool,
    expires_at: Option<i64>,
    publisher: String,
    verified_at: i64,
    authenticated_at_unix_ms: Option<i64>,
    provider: String,
    host: String,
    model: String,
    verification_state: &'static str,
    notary_key_id: Option<String>,
    registry_generation: Option<i64>,
    trust_source: Option<String>,
    content_sha256: String,
    package_size_bytes: i64,
    package_sha256: String,
    disclosure_safety_version: String,
    disclosure_safety_override: bool,
    trace_url: String,
    package_url: String,
    share_url: String,
}

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum ShareReportReason {
    SensitiveInformation,
    Harassment,
    IllegalContent,
    Spam,
    Other,
}

impl ShareReportReason {
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
struct CreateShareReport {
    reason: ShareReportReason,
    #[schema(max_length = 500)]
    message: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ShareReportReceipt {
    received: bool,
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(listed_shares))
        .routes(routes!(public_share_detail))
        .routes(routes!(public_share_trace))
        .routes(routes!(public_share_package))
        .routes(routes!(create_share_report))
}

#[utoipa::path(
    get,
    path = "/api/public/shares",
    summary = "List Listed verified-session shares",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query), ("search" = Option<String>, Query), ("provider" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<ListedShareSummary>),
        (status = 400, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "library"
)]
async fn listed_shares(
    State(state): State<NotaryApiState>,
    query: Result<Query<ListedSharesQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<ListedShareSummary>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let search = normalize_listing_search(query.search)?;
    let search_pattern = search.as_deref().map(listing_search_regex);
    let provider = normalize_listing_filter(query.provider, 100, "provider is too long")?;
    let page_query = PageQuery {
        limit: query.limit,
        cursor: query.cursor,
    };
    let limit = page_query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new(
        "/api/public/shares",
        &(&search, &provider),
        "authenticated_provider_connection_unix_ms desc nulls last, trace_id desc",
    )
    .map_err(pagination::api_error)?;
    let position = page_query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<ListedSharePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let rows: Vec<ListedShareRow> = sqlx::query_as(
        "SELECT traces.trace_id AS id, accounts.display_name AS publisher, traces.provider,
                traces.model,
                traces.authenticated_provider_connection_unix_ms,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.input_preview END AS input_preview,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.output_preview END AS output_preview,
                traces.access_password_hash IS NOT NULL AS password_protected,
                COALESCE(
                    traces.authenticated_provider_connection_unix_ms,
                    '-9223372036854775808'::BIGINT
                ) AS page_authenticated_at_unix_ms
         FROM traces
         JOIN accounts ON accounts.account_id = traces.account_id
         WHERE traces.status = 'shared'
           AND traces.visibility = 'listed'
           AND (traces.access_expires_at IS NULL OR traces.access_expires_at > $6)
           AND traces.content_object_key IS NOT NULL
           AND traces.package_object_key IS NOT NULL
           AND ($1::TEXT IS NULL OR traces.provider = $1)
           AND ($2::TEXT IS NULL OR (
                traces.access_password_hash IS NULL
                AND traces.listing_search_text ~* $2
           ) OR (
                traces.access_password_hash IS NOT NULL
                AND LOWER(CONCAT_WS(
                    ' ', traces.provider, traces.model, accounts.display_name
                )) ~* $2
           ))
           AND ($3::TEXT IS NULL OR (
                COALESCE(
                    traces.authenticated_provider_connection_unix_ms,
                    '-9223372036854775808'::BIGINT
                ), traces.trace_id
           ) < ($4, $3))
         ORDER BY traces.authenticated_provider_connection_unix_ms DESC NULLS LAST,
                  traces.trace_id DESC
         LIMIT $5",
    )
    .bind(&provider)
    .bind(&search_pattern)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(
        position
            .as_ref()
            .map(|position| position.authenticated_at_unix_ms),
    )
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(error.into()))?)
    .bind(unix_timestamp()?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    let page = Page::from_limit_plus_one(rows, limit, &scope, |share| ListedSharePagePosition {
        authenticated_at_unix_ms: share.page_authenticated_at_unix_ms,
        id: share.id.clone(),
    })
    .map_err(pagination::api_error)?;
    let items = page
        .items
        .into_iter()
        .map(|share| ListedShareSummary {
            share_url: canonical_share_url(&state, &share.id),
            id: share.id,
            provider: share.provider,
            model: share.model,
            publisher: share.publisher,
            authenticated_at_unix_ms: share.authenticated_provider_connection_unix_ms,
            input_preview: share.input_preview,
            output_preview: share.output_preview,
            password_protected: share.password_protected,
        })
        .collect();
    Ok(Json(Page {
        items,
        next_cursor: page.next_cursor,
    }))
}

fn normalize_listing_filter(
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

fn normalize_listing_search(value: Option<String>) -> ApiResult<Option<String>> {
    let value = normalize_listing_filter(value, 200, "search is too long")?;
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

fn listing_search_regex(value: &str) -> String {
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
    path = "/api/public/shares/{share_id}",
    summary = "Get one verified-session share by its stable ID",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    responses(
        (status = 200, body = PublicShareDetail),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn public_share_detail(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Response> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let (package_size_bytes, package_sha256, safety_version) = {
        let (_, size, sha256, safety_version) = public_package_metadata(&share)?;
        (size, sha256.to_owned(), safety_version.to_owned())
    };
    let detail = PublicShareDetail {
        id: share.id.clone(),
        visibility: share.visibility.clone(),
        password_protected: share.access_password_hash.is_some(),
        expires_at: share.access_expires_at,
        publisher: share.publisher,
        verified_at: share.verified_at,
        authenticated_at_unix_ms: share.authenticated_provider_connection_unix_ms,
        provider: share.provider,
        host: share.provider_host,
        model: share.model,
        verification_state: "verified",
        notary_key_id: share.verified_notary_key_id,
        registry_generation: share.verified_registry_generation,
        trust_source: share.verified_trust_source,
        content_sha256: share.content_sha256,
        package_size_bytes,
        package_sha256,
        disclosure_safety_version: safety_version,
        disclosure_safety_override: share.disclosure_safety_override,
        trace_url: format!("/api/public/shares/{}/trace.otlp.json", share.id),
        package_url: format!("/api/public/shares/{}/package.llmtrace", share.id),
        share_url: canonical_share_url(&state, &share.id),
    };
    let mut response = Json(detail).into_response();
    add_discovery_headers(&mut response, &share.visibility);
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/api/public/shares/{share_id}/trace.otlp.json",
    summary = "Download the verified canonical OpenTelemetry trace",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    responses(
        (status = 200, body = serde_json::Value, content_type = "application/json"),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn public_share_trace(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Response> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let bytes = load_public_bytes(
        &state,
        &share.content_object_key,
        share.content_size_bytes,
        &share.content_sha256,
    )
    .await?;
    Ok(public_bytes(
        bytes,
        "application/json; charset=utf-8",
        &share.content_sha256,
        None,
        &share.visibility,
    ))
}

#[utoipa::path(
    get,
    path = "/api/public/shares/{share_id}/package.llmtrace",
    summary = "Download the exact verified portable proof package",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    responses(
        (status = 200, body = Vec<u8>, content_type = "application/vnd.exalto.notary.trace-package+zip"),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn public_share_package(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Response> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let (object_key, size_bytes, sha256, _) = public_package_metadata(&share)?;
    let bytes = load_public_bytes(&state, object_key, size_bytes, sha256).await?;
    Ok(public_bytes(
        bytes,
        super::storage::ARCHIVE_CONTENT_TYPE,
        sha256,
        Some(&format!("llm-notary-{share_id}.llmtrace")),
        &share.visibility,
    ))
}

#[utoipa::path(
    post,
    path = "/api/public/shares/{share_id}/reports",
    summary = "Report a published share",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    request_body = CreateShareReport,
    responses(
        (status = 200, body = ShareReportReceipt),
        (status = 400, body = crate::ErrorResponse),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn create_share_report(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
    Json(request): Json<CreateShareReport>,
) -> ApiResult<Json<ShareReportReceipt>> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let message = normalize_report_message(request.message)?;
    let now = unix_timestamp()?;
    enforce_share_request_limit(
        &state,
        &headers,
        peer,
        &share.id,
        now,
        SHARE_REPORT_RATE_LIMIT,
    )
    .await?;
    sqlx::query(
        "INSERT INTO trace_reports
             (report_id, trace_id, reason, message, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(share.id)
    .bind(request.reason.as_str())
    .bind(message)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(Json(ShareReportReceipt { received: true }))
}

async fn load_public_share(
    state: &NotaryApiState,
    headers: &HeaderMap,
    share_id: &str,
    peer: SocketAddr,
) -> ApiResult<PublicShareRow> {
    let share = load_public_share_optional(state, share_id)
        .await?
        .ok_or_else(|| ApiError::not_found("share was not found"))?;
    require_share_password(
        state,
        headers,
        share_id,
        peer,
        share.access_password_hash.as_deref(),
    )
    .await?;
    public_package_metadata(&share)?;
    Ok(share)
}

async fn load_public_share_optional(
    state: &NotaryApiState,
    share_id: &str,
) -> ApiResult<Option<PublicShareRow>> {
    let now = unix_timestamp()?;
    sqlx::query_as(
        "SELECT traces.trace_id AS id, traces.visibility,
                traces.access_expires_at, traces.access_password_hash,
                accounts.display_name AS publisher,
                traces.verified_at, traces.provider,
                traces.provider_host, traces.model,
                traces.authenticated_provider_connection_unix_ms,
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
    .bind(share_id)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)
}

async fn require_share_password(
    state: &NotaryApiState,
    headers: &HeaderMap,
    share_id: &str,
    peer: SocketAddr,
    password_hash: Option<&str>,
) -> ApiResult<()> {
    let Some(password_hash) = password_hash else {
        return Ok(());
    };
    let encoded_password = headers.get(SHARE_PASSWORD_HEADER).ok_or_else(|| {
        ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "share_password_required",
            "This share requires a password",
        )
    })?;
    let now = unix_timestamp()?;
    enforce_share_request_limit(
        state,
        headers,
        peer,
        share_id,
        now,
        SHARE_PASSWORD_RATE_LIMIT,
    )
    .await?;
    let password =
        decode_share_password(encoded_password).map_err(|()| invalid_share_password())?;
    let valid = verify_share_password(password, password_hash.to_owned()).await?;
    if !valid {
        return Err(invalid_share_password());
    }
    Ok(())
}

fn decode_share_password(value: &HeaderValue) -> Result<Vec<u8>, ()> {
    let encoded = value.to_str().map_err(|_| ())?;
    if encoded.len() > MAX_SHARE_PASSWORD_BYTES.div_ceil(3) * 4 {
        return Err(());
    }
    let password = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?;
    if password.len() > MAX_SHARE_PASSWORD_BYTES {
        return Err(());
    }
    Ok(password)
}

async fn verify_share_password(password: Vec<u8>, password_hash: String) -> ApiResult<bool> {
    run_share_password_work(move || {
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

fn invalid_share_password() -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "share_password_invalid",
        "The share password is incorrect",
    )
}

async fn enforce_share_request_limit(
    state: &NotaryApiState,
    headers: &HeaderMap,
    peer: SocketAddr,
    share_id: &str,
    now: i64,
    rate_limit: ShareRateLimit,
) -> ApiResult<()> {
    let subject_key = share_rate_limit_subject_key(state, headers, peer, rate_limit.action)?;
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
    .bind(share_id)
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

pub(super) async fn purge_expired_share_rate_limits(state: &NotaryApiState) -> Result<()> {
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

fn share_rate_limit_subject_key(
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
        SHARE_RATE_LIMIT_KEY_PURPOSE,
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

async fn load_public_bytes(
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

fn canonical_share_url(state: &NotaryApiState, share_id: &str) -> String {
    state
        .public_origin
        .join(&format!("/s/{share_id}"))
        .expect("share path is a valid same-origin URL")
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
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static(SHARE_PASSWORD_HEADER),
    );
    if visibility == "unlisted" {
        response.headers_mut().insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow, noarchive"),
        );
    }
}

fn public_bytes(
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
                .expect("safe share ID makes a valid filename"),
        );
    }
    add_discovery_headers(&mut response, visibility);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_filters_are_normalized_and_bounded() {
        assert_eq!(
            normalize_listing_filter(Some("  OpenAI  ".to_owned()), 100, "too long").unwrap(),
            Some("openai".to_owned())
        );
        assert_eq!(
            normalize_listing_filter(Some("   ".to_owned()), 100, "too long").unwrap(),
            None
        );
        assert!(normalize_listing_filter(Some("x".repeat(101)), 100, "too long").is_err());
        assert!(normalize_listing_search(Some("ai".to_owned())).is_err());
        assert!(normalize_listing_search(Some("%%%".to_owned())).is_err());
        assert!(normalize_listing_search(Some("a-b-c".to_owned())).is_err());
        assert_eq!(
            normalize_listing_search(Some("  GPT  ".to_owned())).unwrap(),
            Some("gpt".to_owned())
        );
        assert_eq!(listing_search_regex("100%_safe!"), "100%_safe!");
        assert_eq!(listing_search_regex("a.b[c]"), "a\\.b\\[c\\]");
    }

    async fn insert_listed_trace(
        pool: &sqlx::PgPool,
        id: &str,
        visibility: &str,
        provider: &str,
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
                 $1, 'listed-user', $1 || '-source', $1 || '-key', 'shared', $2,
                 1, $3, $1 || '-upload', $1 || '-intake', 10, 1, 1,
                 1, 1, $3, $1 || '-trace', 1, $4, $5,
                 $1 || '-package', 1, $6, 'notary/public-package-safety/v1',
                 $7, $7 || '.example.com', 'model-' || $1, $8,
                 'input ' || $1, 'output ' || $1, $9
             )",
        )
        .bind(id)
        .bind(crate::traces::storage::PACKAGE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind(visibility)
        .bind("c".repeat(64))
        .bind(provider)
        .bind(authenticated_at)
        .bind(search_text)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn listed_share_route_pages_ties_nulls_filters_and_concurrent_inserts() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "listed-user", 1, "publisher").await;
        insert_listed_trace(
            &database.pool,
            "share-c",
            "listed",
            "openai",
            Some(100),
            "openai publisher 100%_safe! prompt",
        )
        .await;
        insert_listed_trace(
            &database.pool,
            "share-b",
            "listed",
            "openai",
            Some(100),
            "openai publisher 100xxsafe prompt",
        )
        .await;
        insert_listed_trace(
            &database.pool,
            "share-a",
            "listed",
            "anthropic",
            Some(90),
            "anthropic publisher",
        )
        .await;
        insert_listed_trace(
            &database.pool,
            "share-null",
            "listed",
            "openai",
            None,
            "openai publisher without timestamp",
        )
        .await;
        insert_listed_trace(
            &database.pool,
            "hidden",
            "unlisted",
            "openai",
            Some(95),
            "openai publisher hidden",
        )
        .await;
        let state = NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: url::Url::parse(
                "https://notary.exalto.ai/api/auth/github/callback",
            )
            .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: url::Url::parse(
                "https://notary.exalto.ai/api/auth/google/callback",
            )
            .unwrap(),
            public_origin: url::Url::parse("https://notary.exalto.ai").unwrap(),
            secure_cookies: true,
            registry: crate::tests::test_registry(),
            traces: crate::traces::owner::TraceService::disabled_for_test(),
            admission: std::sync::Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        };

        let first = listed_shares(
            State(state.clone()),
            Ok(Query(ListedSharesQuery {
                limit: Some(2),
                cursor: None,
                search: None,
                provider: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            first
                .items
                .iter()
                .map(|share| share.id.as_str())
                .collect::<Vec<_>>(),
            ["share-c", "share-b"]
        );
        let cursor = first.next_cursor.unwrap();

        insert_listed_trace(
            &state.database,
            "share-new",
            "listed",
            "openai",
            Some(200),
            "openai publisher inserted later",
        )
        .await;
        let second = listed_shares(
            State(state.clone()),
            Ok(Query(ListedSharesQuery {
                limit: Some(2),
                cursor: Some(cursor),
                search: None,
                provider: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            second
                .items
                .iter()
                .map(|share| share.id.as_str())
                .collect::<Vec<_>>(),
            ["share-a", "share-null"]
        );
        assert!(second.next_cursor.is_none());

        let literal_search = listed_shares(
            State(state.clone()),
            Ok(Query(ListedSharesQuery {
                limit: None,
                cursor: None,
                search: Some("100%_safe!".to_owned()),
                provider: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(literal_search.items.len(), 1);
        assert_eq!(literal_search.items[0].id, "share-c");

        let provider_filter = listed_shares(
            State(state),
            Ok(Query(ListedSharesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: Some("ANTHROPIC".to_owned()),
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(provider_filter.items.len(), 1);
        assert_eq!(provider_filter.items[0].id, "share-a");
    }

    #[test]
    fn unlisted_artifacts_are_noindex_but_still_downloadable() {
        let response = public_bytes(
            b"package".to_vec(),
            crate::traces::storage::ARCHIVE_CONTENT_TYPE,
            &"a".repeat(64),
            Some("llm-notary-share.llmtrace"),
            "unlisted",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-robots-tag").unwrap(),
            "noindex, nofollow, noarchive"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"llm-notary-share.llmtrace\""
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
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
    async fn protected_share_passwords_round_trip_utf8_and_bound_verification() {
        use argon2::{
            PasswordHasher,
            password_hash::{SaltString, rand_core::OsRng},
        };

        let password = "пароль\n🔐123";
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        let encoded = URL_SAFE_NO_PAD.encode(password.as_bytes());
        let header = HeaderValue::from_str(&encoded).unwrap();
        let decoded = decode_share_password(&header).unwrap();
        assert_eq!(decoded, password.as_bytes());
        assert!(verify_share_password(decoded, hash.clone()).await.unwrap());

        let wrong = URL_SAFE_NO_PAD.encode("wrong-password".as_bytes());
        let wrong = decode_share_password(&HeaderValue::from_str(&wrong).unwrap()).unwrap();
        assert!(!verify_share_password(wrong, hash.clone()).await.unwrap());

        let capacity = Arc::new(Semaphore::new(1));
        let _held = capacity.clone().acquire_owned().await.unwrap();
        let saturated =
            crate::traces::owner::run_share_password_work_with_capacity(capacity, || true).await;
        assert!(matches!(
            saturated,
            Err(ApiError {
                code: "share_password_capacity",
                ..
            })
        ));

        let oversized = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_SHARE_PASSWORD_BYTES + 1]);
        assert!(decode_share_password(&HeaderValue::from_str(&oversized).unwrap()).is_err());
        assert!(decode_share_password(&HeaderValue::from_static("not base64")).is_err());
        assert!(
            !verify_share_password(password.as_bytes().to_vec(), "invalid-hash".to_owned())
                .await
                .unwrap()
        );
    }
}
