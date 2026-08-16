use anyhow::anyhow;
use axum::extract::rejection::QueryRejection;
use axum::http::StatusCode;
use llm_notary_core::pagination::PaginationError;

use super::ApiError;

pub(super) const DEFAULT_PAGE_LIMIT: usize = 50;
pub(super) const MAX_PAGE_LIMIT: usize = 100;

pub(super) fn query_error(_error: QueryRejection) -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        "invalid_query_parameter",
        "query parameters are invalid",
    )
}

pub(super) fn api_error(error: PaginationError) -> ApiError {
    if !error.is_client_error() {
        return ApiError::internal(anyhow!(error));
    }
    let message = match error {
        PaginationError::InvalidLimit { .. } => "page limit must be between 1 and 100",
        PaginationError::CursorTooLong => "cursor exceeds the maximum length",
        PaginationError::MalformedCursor | PaginationError::CursorChecksum => "cursor is invalid",
        PaginationError::UnsupportedCursorVersion => "cursor version is not supported",
        PaginationError::CursorScope => "cursor does not belong to this route and filter set",
        PaginationError::InvalidPage
        | PaginationError::Serialization
        | PaginationError::InvalidConfiguration => unreachable!("handled as server errors"),
    };
    ApiError::coded(StatusCode::BAD_REQUEST, error.code(), message)
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, extract::Query, http::Uri, response::IntoResponse};
    use llm_notary_core::pagination::PageQuery;

    use super::query_error;

    #[tokio::test]
    async fn malformed_pagination_query_uses_the_api_error_envelope() {
        let uri: Uri = "/?limit=-1".parse().unwrap();
        let rejection = Query::<PageQuery>::try_from_uri(&uri).unwrap_err();
        let response = query_error(rejection).into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1_024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error": "invalid_query_parameter",
                "message": "query parameters are invalid"
            })
        );
    }
}
