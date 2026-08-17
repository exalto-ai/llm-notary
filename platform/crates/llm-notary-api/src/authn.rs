use std::collections::BTreeSet;

use axum::http::HeaderMap;
use k256::elliptic_curve::subtle::ConstantTimeEq as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use utoipa::ToSchema;

use super::{ApiError, ApiResult, AppState, bearer_token, database_error, unix_timestamp};

pub(crate) const API_KEY_VERSION_PREFIX: &str = "llmn_v1_";
const API_KEY_ID_HEX_BYTES: usize = 32;
const API_KEY_SECRET_HEX_BYTES: usize = 64;
const LAST_USED_UPDATE_INTERVAL_SECS: i64 = 5 * 60;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, ToSchema)]
pub(crate) enum ApiScope {
    #[serde(rename = "account:read")]
    AccountRead,
    #[serde(rename = "notary:admit")]
    NotaryAdmit,
    #[serde(rename = "publish:read")]
    PublishRead,
    #[serde(rename = "publish:write")]
    PublishWrite,
}

impl ApiScope {
    pub(crate) const ALL: [Self; 4] = [
        Self::AccountRead,
        Self::NotaryAdmit,
        Self::PublishRead,
        Self::PublishWrite,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AccountRead => "account:read",
            Self::NotaryAdmit => "notary:admit",
            Self::PublishRead => "publish:read",
            Self::PublishWrite => "publish:write",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredentialKind {
    CliSession,
    ApiKey,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedPrincipal {
    pub(crate) user_id: String,
    pub(crate) credential_kind: CredentialKind,
    pub(crate) credential_id: String,
    pub(crate) credential_name: String,
    scopes: BTreeSet<ApiScope>,
}

impl AuthenticatedPrincipal {
    fn cli_session(user_id: String, session_id: String, device_name: String) -> Self {
        Self {
            user_id,
            credential_kind: CredentialKind::CliSession,
            credential_id: session_id,
            credential_name: device_name,
            scopes: ApiScope::ALL.into_iter().collect(),
        }
    }

    fn api_key(
        user_id: String,
        key_id: String,
        name: String,
        scopes: Vec<String>,
    ) -> ApiResult<Self> {
        let scopes = scopes
            .iter()
            .map(|scope| {
                ApiScope::parse(scope).ok_or_else(|| {
                    ApiError::internal(anyhow::anyhow!(
                        "database contains an invalid API key scope"
                    ))
                })
            })
            .collect::<ApiResult<BTreeSet<_>>>()?;
        Ok(Self {
            user_id,
            credential_kind: CredentialKind::ApiKey,
            credential_id: key_id,
            credential_name: name,
            scopes,
        })
    }

    fn require_scope(self, required: ApiScope) -> ApiResult<Self> {
        if !self.scopes.contains(&required) {
            return Err(ApiError::forbidden());
        }
        Ok(self)
    }
}

pub(crate) async fn authenticated_principal(
    state: &AppState,
    headers: &HeaderMap,
    required: ApiScope,
) -> ApiResult<AuthenticatedPrincipal> {
    let token = bearer_token(headers)?;
    resolve_token(state, token).await?.require_scope(required)
}

pub(crate) async fn optional_authenticated_principal(
    state: &AppState,
    headers: &HeaderMap,
    required: ApiScope,
) -> ApiResult<Option<AuthenticatedPrincipal>> {
    if !headers.contains_key(axum::http::header::AUTHORIZATION) {
        return Ok(None);
    }
    authenticated_principal(state, headers, required)
        .await
        .map(Some)
}

async fn resolve_token(state: &AppState, token: &str) -> ApiResult<AuthenticatedPrincipal> {
    if token.starts_with(API_KEY_VERSION_PREFIX) {
        return resolve_api_key(state, token).await;
    }

    let now = unix_timestamp()?;
    let session = sqlx::query_as::<_, (String, String, String)>(
        "SELECT cli_sessions.user_id, cli_sessions.id, cli_sessions.device_name
         FROM cli_access_tokens
         JOIN cli_sessions ON cli_sessions.id = cli_access_tokens.session_id
         WHERE cli_access_tokens.token_hash = $1 AND cli_access_tokens.expires_at > $2
           AND cli_sessions.revoked_at IS NULL AND cli_sessions.expires_at > $2",
    )
    .bind(notary_core::sha256_hex(token.as_bytes()))
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)?;
    Ok(AuthenticatedPrincipal::cli_session(
        session.0, session.1, session.2,
    ))
}

async fn resolve_api_key(state: &AppState, token: &str) -> ApiResult<AuthenticatedPrincipal> {
    let (key_id, secret) = parse_api_key(token).ok_or_else(ApiError::unauthorized)?;
    let now = unix_timestamp()?;
    let row = sqlx::query_as::<_, (String, String, Vec<u8>, Vec<String>)>(
        "SELECT user_id, name, secret_hash, scopes
         FROM api_keys
         WHERE id = $1 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(key_id)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;

    // Perform the same hash and constant-time comparison even when the opaque
    // lookup ID is unknown, expired, or revoked.
    let supplied_hash = Sha256::digest(secret.as_bytes());
    let missing_hash = [0_u8; 32];
    let expected_hash = row
        .as_ref()
        .map(|row| row.2.as_slice())
        .unwrap_or(missing_hash.as_slice());
    if expected_hash.len() != supplied_hash.len()
        || !bool::from(supplied_hash.as_slice().ct_eq(expected_hash))
    {
        return Err(ApiError::unauthorized());
    }
    let Some((user_id, name, _, scopes)) = row else {
        return Err(ApiError::unauthorized());
    };

    sqlx::query(
        "UPDATE api_keys SET last_used_at = $1
         WHERE id = $2 AND (last_used_at IS NULL OR last_used_at <= $3)",
    )
    .bind(now)
    .bind(key_id)
    .bind(now - LAST_USED_UPDATE_INTERVAL_SECS)
    .execute(&state.database)
    .await
    .map_err(database_error)?;

    AuthenticatedPrincipal::api_key(user_id, key_id.to_owned(), name, scopes)
}

pub(crate) fn parse_api_key(token: &str) -> Option<(&str, &str)> {
    let value = token.strip_prefix(API_KEY_VERSION_PREFIX)?;
    let (key_id, secret) = value.split_once('_')?;
    if is_lower_hex(key_id, API_KEY_ID_HEX_BYTES) && is_lower_hex(secret, API_KEY_SECRET_HEX_BYTES)
    {
        Some((key_id, secret))
    } else {
        None
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_versioned_bounded_key_shape() {
        let id = "a".repeat(API_KEY_ID_HEX_BYTES);
        let secret = "b".repeat(API_KEY_SECRET_HEX_BYTES);
        let token = format!("{API_KEY_VERSION_PREFIX}{id}_{secret}");
        assert_eq!(parse_api_key(&token), Some((id.as_str(), secret.as_str())));

        for invalid in [
            format!("{API_KEY_VERSION_PREFIX}{id}"),
            format!("{API_KEY_VERSION_PREFIX}{id}_short"),
            format!("{API_KEY_VERSION_PREFIX}{}_{secret}", "A".repeat(32)),
            format!("other_v1_{id}_{secret}"),
        ] {
            assert!(parse_api_key(&invalid).is_none(), "accepted {invalid}");
        }
    }
}
