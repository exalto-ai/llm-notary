use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, authenticated_web_user,
    authn::{API_KEY_VERSION_PREFIX, ApiScope},
    database_error, random_token, unix_timestamp,
};

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

#[derive(Debug, Serialize, ToSchema)]
struct ApiKeysResponse {
    api_keys: Vec<ApiKeyResponse>,
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

pub(super) fn router() -> OpenApiRouter<AppState> {
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
    State(state): State<AppState>,
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
    let id = Uuid::new_v4().simple().to_string();
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
         (id, display_prefix, user_id, name, secret_hash, scopes, created_at, expires_at)
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
    responses(
        (status = 200, body = ApiKeysResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn list_api_keys(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<ApiKeysResponse>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, display_prefix, name, scopes, created_at, last_used_at, expires_at, revoked_at
         FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(&user.0)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    let api_keys = rows
        .into_iter()
        .map(api_key_response)
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(ApiKeysResponse { api_keys }))
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
    State(state): State<AppState>,
    jar: CookieJar,
    Path(api_key_id): Path<String>,
) -> ApiResult<StatusCode> {
    let user = authenticated_web_user(&state, &jar).await?;
    let revoked = sqlx::query(
        "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $1)
         WHERE id = $2 AND user_id = $3",
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
        let values = vec!["publish:write".to_owned(), "account:read".to_owned()];
        assert_eq!(
            parse_scopes(&values).unwrap(),
            vec![ApiScope::AccountRead, ApiScope::PublishWrite]
        );
        assert!(parse_scopes(&[]).is_err());
        assert!(parse_scopes(&["admin".to_owned()]).is_err());
        assert!(parse_scopes(&["account:read".to_owned(), "account:read".to_owned()]).is_err());
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn keys_are_one_time_scoped_revocable_expiring_and_account_isolated() {
        let database = super::super::fresh_database().await;
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'one', 1, 1), ('user-2', 2, 'two', 1, 1)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let now = unix_timestamp().unwrap();
        for (token, user_id) in [("web-one", "user-1"), ("web-two", "user-2")] {
            sqlx::query(
                "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(llm_notary_core::sha256_hex(token.as_bytes()))
            .bind(user_id)
            .bind(now + 600)
            .bind(now)
            .execute(&database.pool)
            .await
            .unwrap();
        }
        let state = AppState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: url::Url::parse("https://llm-notary.exalto.ai/api/auth/github/callback")
                .unwrap(),
            app_url: url::Url::parse("https://llm-notary.exalto.ai").unwrap(),
            secure_cookies: true,
            notary_directory: super::super::tests::directory_key(),
            publish: super::super::publish::PublishService::disabled_for_test(),
            admission: std::sync::Arc::new(super::super::config::AdmissionConfig::for_test()),
        };
        let jar = |token| CookieJar::new().add(Cookie::new(SESSION_COOKIE, token));
        let request = || CreateApiKeyRequest {
            name: "CI release".to_owned(),
            scopes: vec!["account:read".to_owned(), "publish:read".to_owned()],
            expires_at: None,
        };

        let (_, first) = create_api_key(State(state.clone()), jar("web-one"), Json(request()))
            .await
            .unwrap();
        let (_, second) = create_api_key(State(state.clone()), jar("web-one"), Json(request()))
            .await
            .unwrap();
        assert_ne!(first.secret, second.secret, "manual rotation may overlap");
        let stored: Vec<u8> = sqlx::query_scalar("SELECT secret_hash FROM api_keys WHERE id = $1")
            .bind(&first.api_key.id)
            .fetch_one(&state.database)
            .await
            .unwrap();
        assert_ne!(stored, first.secret.as_bytes());

        let listed = list_api_keys(State(state.clone()), jar("web-one"))
            .await
            .unwrap();
        assert_eq!(listed.api_keys.len(), 2);
        assert!(listed.api_keys.iter().all(|key| key.revoked_at.is_none()));
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
            super::super::authn::authenticated_principal(&state, &headers, ApiScope::AccountRead)
                .await
                .unwrap();
        assert_eq!(principal.user_id, "user-1");
        assert_eq!(
            principal.credential_kind,
            super::super::authn::CredentialKind::ApiKey
        );
        let first_used_at: Option<i64> =
            sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id = $1")
                .bind(&first.api_key.id)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert!(first_used_at.is_some());
        super::super::authn::authenticated_principal(&state, &headers, ApiScope::AccountRead)
            .await
            .unwrap();
        let second_used_at: Option<i64> =
            sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id = $1")
                .bind(&first.api_key.id)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(first_used_at, second_used_at, "last use is coarsened");
        assert!(matches!(
            super::super::authn::authenticated_principal(&state, &headers, ApiScope::PublishWrite,)
                .await,
            Err(ApiError {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        assert!(matches!(
            super::super::authn::optional_authenticated_principal(
                &state,
                &headers,
                ApiScope::NotaryAdmit,
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
            super::super::authn::authenticated_principal(&state, &headers, ApiScope::AccountRead,)
                .await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));

        sqlx::query("UPDATE api_keys SET expires_at = $1 WHERE id = $2")
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
            super::super::authn::authenticated_principal(&state, &headers, ApiScope::AccountRead,)
                .await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));

        let anonymous = HeaderMap::new();
        assert!(
            super::super::authn::optional_authenticated_principal(
                &state,
                &anonymous,
                ApiScope::NotaryAdmit,
            )
            .await
            .unwrap()
            .is_none()
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer llmn_v1_malformed"),
        );
        assert!(matches!(
            super::super::authn::optional_authenticated_principal(
                &state,
                &headers,
                ApiScope::NotaryAdmit,
            )
            .await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));
    }
}
