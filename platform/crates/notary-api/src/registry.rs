//! Official Notary Registry HTTP representation.

use super::*;

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new().routes(routes!(notary))
}

#[utoipa::path(
    get,
    path = "/api/notary",
    summary = "Get the versioned notary directory",
    responses((status = 200, body = RegistryResponse)),
    tag = "health"
)]
pub(super) async fn notary(State(state): State<NotaryApiState>) -> Json<RegistryResponse> {
    Json(state.registry.into())
}
