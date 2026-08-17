use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, ApiResult, NotaryApiState,
    auth::{API_KEY_VERSION_PREFIX, ApiScope, authenticated_web_user},
    database_error, pagination, random_token, typed_id, unix_timestamp,
};
use notary_core::pagination::{CursorScope, Page, PageQuery, decode_cursor};

const MAX_API_KEY_NAME_BYTES: usize = 100;
const DISPLAY_ID_BYTES: usize = 12;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateApiKeyRequest {
    name: String,
    scopes: Vec<String>,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
struct CreateApiKeyResponse {
    api_key: ApiKeyResponse,
    secret: String,
}

#[derive(Deserialize, Serialize)]
struct ApiKeyPagePosition {
    created_at: i64,
    id: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ApiKeyResponse {
    id: String,
    prefix: String,
    name: String,
    scopes: Vec<ApiScope>,
    created_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
}

type ApiKeyRow = (
    String,
    String,
    String,
    Vec<String>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(create_api_key, list_api_keys))
        .routes(routes!(revoke_api_key))
}

#[utoipa::path(
    post,
    path = "/api/me/api-keys",
    summary = "Create an account API key",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, body = CreateApiKeyResponse),
        (status = 400, body = super::ErrorResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn create_api_key(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Json(request): Json<CreateApiKeyRequest>,
) -> ApiResult<(StatusCode, Json<CreateApiKeyResponse>)> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let name = request.name.trim();
    if name.is_empty() || name.len() > MAX_API_KEY_NAME_BYTES {
        return Err(ApiError::bad_request(
            "API key name must contain between 1 and 100 bytes",
        ));
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(ApiError::bad_request(
            "API key expiration must be in the future",
        ));
    }
    let scopes = parse_scopes(&request.scopes)?;
    let id = typed_id("key-");
    let prefix = format!("{API_KEY_VERSION_PREFIX}{}", &id[..DISPLAY_ID_BYTES]);
    let secret_part = random_token();
    let secret = format!("{API_KEY_VERSION_PREFIX}{id}_{secret_part}");
    let secret_hash = Sha256::digest(secret_part.as_bytes()).to_vec();
    let scope_names = scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO api_keys
         (key_id, display_prefix, account_id, name, secret_hash, scopes, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&prefix)
    .bind(&user.0)
    .bind(name)
    .bind(secret_hash)
    .bind(&scope_names)
    .bind(now)
    .bind(request.expires_at)
    .execute(&state.database)
    .await
    .map_err(database_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            api_key: ApiKeyResponse {
                id,
                prefix,
                name: name.to_owned(),
                scopes,
                created_at: now,
                last_used_at: None,
                expires_at: request.expires_at,
                revoked_at: None,
            },
            secret,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/me/api-keys",
    summary = "List account API keys",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<ApiKeyResponse>),
        (status = 400, body = super::ErrorResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn list_api_keys(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<ApiKeyResponse>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let user = authenticated_web_user(&state, &jar).await?;
    let limit = query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new("/api/me/api-keys", &user.0, "created_at desc, id desc")
        .map_err(pagination::api_error)?;
    let position = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<ApiKeyPagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT key_id, display_prefix, name, scopes, created_at, last_used_at, expires_at, revoked_at
         FROM api_keys WHERE account_id = $1
           AND ($2::TEXT IS NULL OR (created_at, key_id) < ($3, $2))
         ORDER BY created_at DESC, key_id DESC LIMIT $4",
    )
    .bind(&user.0)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(position.as_ref().map(|position| position.created_at))
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(error.into()))?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    let api_keys = rows
        .into_iter()
        .map(api_key_response)
        .collect::<ApiResult<Vec<_>>>()?;
    let page = Page::from_limit_plus_one(api_keys, limit, &scope, |api_key| ApiKeyPagePosition {
        created_at: api_key.created_at,
        id: api_key.id.clone(),
    })
    .map_err(pagination::api_error)?;
    Ok(Json(page))
}

#[utoipa::path(
    delete,
    path = "/api/me/api-keys/{api_key_id}",
    summary = "Revoke an account API key",
    params(("api_key_id" = String, Path)),
    responses(
        (status = 204, description = "API key revoked"),
        (status = 401, body = super::ErrorResponse),
        (status = 404, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn revoke_api_key(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(api_key_id): Path<String>,
) -> ApiResult<StatusCode> {
    let user = authenticated_web_user(&state, &jar).await?;
    let revoked = sqlx::query(
        "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $1)
         WHERE key_id = $2 AND account_id = $3",
    )
    .bind(unix_timestamp()?)
    .bind(api_key_id)
    .bind(user.0)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if revoked.rows_affected() != 1 {
        return Err(ApiError::not_found("API key was not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

fn parse_scopes(values: &[String]) -> ApiResult<Vec<ApiScope>> {
    let scopes = values
        .iter()
        .map(|value| {
            ApiScope::parse(value)
                .ok_or_else(|| ApiError::bad_request("API key scope is not supported"))
        })
        .collect::<ApiResult<BTreeSet<_>>>()?;
    if scopes.is_empty() {
        return Err(ApiError::bad_request(
            "API key must have at least one scope",
        ));
    }
    if scopes.len() != values.len() {
        return Err(ApiError::bad_request("API key scopes must be unique"));
    }
    Ok(scopes.into_iter().collect())
}

fn api_key_response(row: ApiKeyRow) -> ApiResult<ApiKeyResponse> {
    let scopes = row
        .3
        .iter()
        .map(|scope| {
            ApiScope::parse(scope).ok_or_else(|| {
                ApiError::internal(anyhow::anyhow!(
                    "database contains an invalid API key scope"
                ))
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(ApiKeyResponse {
        id: row.0,
        prefix: row.1,
        name: row.2,
        scopes,
        created_at: row.4,
        last_used_at: row.5,
        expires_at: row.6,
        revoked_at: row.7,
    })
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use axum_extra::extract::cookie::Cookie;

    use super::*;
    use crate::SESSION_COOKIE;

    #[test]
    fn scopes_are_allowlisted_unique_and_canonical() {
        let values = vec!["traces:share".to_owned(), "account:read".to_owned()];
        assert_eq!(
            parse_scopes(&values).unwrap(),
            vec![ApiScope::AccountRead, ApiScope::TracesShare]
        );
        assert!(parse_scopes(&[]).is_err());
        assert!(parse_scopes(&["admin".to_owned()]).is_err());
        assert!(parse_scopes(&["account:read".to_owned(), "account:read".to_owned()]).is_err());
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn keys_are_one_time_scoped_revocable_expiring_and_account_isolated() {
        let database = super::super::fresh_database().await;
        super::super::insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        super::super::insert_test_github_user(&database.pool, "user-2", 2, "two").await;
        let now = unix_timestamp().unwrap();
        for (token, account_id) in [("web-one", "user-1"), ("web-two", "user-2")] {
            sqlx::query(
                "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(notary_core::sha256_hex(token.as_bytes()))
            .bind(account_id)
            .bind(now + 600)
            .bind(now)
            .execute(&database.pool)
            .await
            .unwrap();
        }
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
            registry: super::super::tests::directory_key(),
            traces: super::super::traces::owner::TraceService::disabled_for_test(),
            admission: std::sync::Arc::new(super::super::config::NotaryAdmissionConfig::for_test()),
            billing: super::super::billing::BillingService::disabled_for_test(),
        };
        let jar = |token| CookieJar::new().add(Cookie::new(SESSION_COOKIE, token));
        let request = || CreateApiKeyRequest {
            name: "CI release".to_owned(),
            scopes: vec!["account:read".to_owned(), "traces:read".to_owned()],
            expires_at: None,
        };

        let (_, first) = create_api_key(State(state.clone()), jar("web-one"), Json(request()))
            .await
            .unwrap();
        let (_, second) = create_api_key(State(state.clone()), jar("web-one"), Json(request()))
            .await
            .unwrap();
        assert_ne!(first.secret, second.secret, "manual rotation may overlap");
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT secret_hash FROM api_keys WHERE key_id = $1")
                .bind(&first.api_key.id)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_ne!(stored, first.secret.as_bytes());

        let first_page = list_api_keys(
            State(state.clone()),
            jar("web-one"),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: None,
            })),
        )
        .await
        .unwrap();
        assert_eq!(first_page.items.len(), 1);
        let cursor = first_page.next_cursor.clone().expect("next key page");

        let (_, inserted_between_pages) =
            create_api_key(State(state.clone()), jar("web-one"), Json(request()))
                .await
                .unwrap();
        let second_page = list_api_keys(
            State(state.clone()),
            jar("web-one"),
            Ok(Query(PageQuery {
                limit: Some(100),
                cursor: Some(cursor.clone()),
            })),
        )
        .await
        .unwrap();
        assert!(
            second_page
                .items
                .iter()
                .all(|key| key.id != first_page.items[0].id)
        );
        assert!(
            second_page
                .items
                .iter()
                .any(|key| key.id == first.api_key.id || key.id == second.api_key.id)
        );
        assert!(second_page.next_cursor.is_none());

        let cross_account = list_api_keys(
            State(state.clone()),
            jar("web-two"),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: Some(cursor),
            })),
        )
        .await;
        assert!(matches!(
            cross_account,
            Err(ApiError {
                code: "cursor_scope_mismatch",
                ..
            })
        ));
        let malformed = list_api_keys(
            State(state.clone()),
            jar("web-one"),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: Some("not-a-cursor".to_owned()),
            })),
        )
        .await;
        assert!(matches!(
            malformed,
            Err(ApiError {
                code: "invalid_cursor",
                ..
            })
        ));

        let listed = list_api_keys(
            State(state.clone()),
            jar("web-one"),
            Ok(Query(PageQuery::default())),
        )
        .await
        .unwrap();
        assert_eq!(listed.items.len(), 3);
        assert!(listed.items.iter().all(|key| key.revoked_at.is_none()));
        assert!(
            listed
                .items
                .iter()
                .any(|key| key.id == inserted_between_pages.api_key.id)
        );
        assert!(
            !serde_json::to_string(&listed.0)
                .unwrap()
                .contains(&first.secret)
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", first.secret)).unwrap(),
        );
        let principal =
            super::super::auth::authenticated_principal(&state, &headers, ApiScope::AccountRead)
                .await
                .unwrap();
        assert_eq!(principal.account_id, "user-1");
        assert_eq!(
            principal.credential_kind,
            super::super::auth::CredentialKind::ApiKey
        );
        let first_used_at: Option<i64> =
            sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE key_id = $1")
                .bind(&first.api_key.id)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert!(first_used_at.is_some());
        super::super::auth::authenticated_principal(&state, &headers, ApiScope::AccountRead)
            .await
            .unwrap();
        let second_used_at: Option<i64> =
            sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE key_id = $1")
                .bind(&first.api_key.id)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(first_used_at, second_used_at, "last use is coarsened");
        assert!(matches!(
            super::super::auth::authenticated_principal(&state, &headers, ApiScope::TracesShare,)
                .await,
            Err(ApiError {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        assert!(matches!(
            super::super::auth::optional_authenticated_principal(
                &state,
                &headers,
                ApiScope::NotarizationRequest,
            )
            .await,
            Err(ApiError {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));

        let cross_account = revoke_api_key(
            State(state.clone()),
            jar("web-two"),
            Path(first.api_key.id.clone()),
        )
        .await;
        assert!(matches!(
            cross_account,
            Err(ApiError {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ));
        revoke_api_key(
            State(state.clone()),
            jar("web-one"),
            Path(first.api_key.id.clone()),
        )
        .await
        .unwrap();
        assert!(matches!(
            super::super::auth::authenticated_principal(&state, &headers, ApiScope::AccountRead,)
                .await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));

        sqlx::query("UPDATE api_keys SET expires_at = $1 WHERE key_id = $2")
            .bind(now - 1)
            .bind(&second.api_key.id)
            .execute(&state.database)
            .await
            .unwrap();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", second.secret)).unwrap(),
        );
        assert!(matches!(
            super::super::auth::authenticated_principal(&state, &headers, ApiScope::AccountRead,)
                .await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));

        let anonymous = HeaderMap::new();
        assert!(
            super::super::auth::optional_authenticated_principal(
                &state,
                &anonymous,
                ApiScope::NotarizationRequest,
            )
            .await
            .unwrap()
            .is_none()
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer notary_key_malformed"),
        );
        assert!(matches!(
            super::super::auth::optional_authenticated_principal(
                &state,
                &headers,
                ApiScope::NotarizationRequest,
            )
            .await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));
    }
}
