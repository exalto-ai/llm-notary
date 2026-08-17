//! Official Notary Registry HTTP representation.

use super::*;
use notary_core::registry::{NotaryKeyStatus, NotaryTransport, Registry, RegistryRecord};
use serde::Deserialize;

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistryResponse {
    format: String,
    generation: u64,
    active_key_id: String,
    notaries: Vec<RegistryRecordResponse>,
}

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct RegistryRecordResponse {
    name: String,
    operator: String,
    host: String,
    port: u16,
    transport: NotaryTransportResponse,
    key_id: String,
    verification_key: String,
    status: NotaryKeyStatusResponse,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: Option<u64>,
    notarize_until_unix_ms: Option<u64>,
}

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum NotaryTransportResponse {
    Tcp,
    Tls,
}

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum NotaryKeyStatusResponse {
    Active,
    Retiring,
    Retired,
    Revoked,
}

impl From<Registry> for RegistryResponse {
    fn from(registry: Registry) -> Self {
        Self {
            format: registry.format,
            generation: registry.generation,
            active_key_id: registry.active_key_id,
            notaries: registry.notaries.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RegistryRecord> for RegistryRecordResponse {
    fn from(record: RegistryRecord) -> Self {
        Self {
            name: record.name,
            operator: record.operator,
            host: record.host,
            port: record.port,
            transport: match record.transport {
                NotaryTransport::Tcp => NotaryTransportResponse::Tcp,
                NotaryTransport::Tls => NotaryTransportResponse::Tls,
            },
            key_id: record.key_id,
            verification_key: record.public_key,
            status: match record.status {
                NotaryKeyStatus::Active => NotaryKeyStatusResponse::Active,
                NotaryKeyStatus::Retiring => NotaryKeyStatusResponse::Retiring,
                NotaryKeyStatus::Retired => NotaryKeyStatusResponse::Retired,
                NotaryKeyStatus::Revoked => NotaryKeyStatusResponse::Revoked,
            },
            valid_from_unix_ms: record.valid_from_unix_ms,
            valid_until_unix_ms: record.valid_until_unix_ms,
            notarize_until_unix_ms: record.notarize_until_unix_ms,
        }
    }
}

impl From<RegistryResponse> for Registry {
    fn from(document: RegistryResponse) -> Self {
        Self {
            format: document.format,
            generation: document.generation,
            active_key_id: document.active_key_id,
            notaries: document.notaries.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RegistryRecordResponse> for RegistryRecord {
    fn from(record: RegistryRecordResponse) -> Self {
        Self {
            name: record.name,
            operator: record.operator,
            host: record.host,
            port: record.port,
            transport: match record.transport {
                NotaryTransportResponse::Tcp => NotaryTransport::Tcp,
                NotaryTransportResponse::Tls => NotaryTransport::Tls,
            },
            key_id: record.key_id,
            public_key: record.verification_key,
            status: match record.status {
                NotaryKeyStatusResponse::Active => NotaryKeyStatus::Active,
                NotaryKeyStatusResponse::Retiring => NotaryKeyStatus::Retiring,
                NotaryKeyStatusResponse::Retired => NotaryKeyStatus::Retired,
                NotaryKeyStatusResponse::Revoked => NotaryKeyStatus::Revoked,
            },
            valid_from_unix_ms: record.valid_from_unix_ms,
            valid_until_unix_ms: record.valid_until_unix_ms,
            notarize_until_unix_ms: record.notarize_until_unix_ms,
        }
    }
}

pub(super) fn parse_registry_document(bytes: &[u8]) -> Result<Registry> {
    let document: RegistryResponse =
        serde_json::from_slice(bytes).context("Registry JSON is invalid")?;
    let internal = Registry::from(document);
    let internal_json =
        serde_json::to_vec(&internal).context("normalizing Registry configuration")?;
    notary_core::registry::parse_registry(&internal_json)
}

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new().routes(routes!(get_registry))
}

#[utoipa::path(
    get,
    path = "/api/registry",
    summary = "Get the versioned Registry of Official Notaries",
    responses((status = 200, body = RegistryResponse)),
    tag = "registry"
)]
pub(super) async fn get_registry(State(state): State<NotaryApiState>) -> Json<RegistryResponse> {
    Json(state.registry.into())
}
