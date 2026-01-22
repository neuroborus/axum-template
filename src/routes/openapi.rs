use axum::Router;
use utoipa::OpenApi;

use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "{{project-name}} API",
        version = "0.1.0",
        license(
            name = "MIT",
            identifier = "MIT"
        )
    ),
    paths(
        crate::handlers::ops::get_health,
        crate::handlers::ops::get_ready,
        crate::handlers::ops::get_metrics,
        crate::handlers::ops::get_build
    ),
    components(schemas(
        crate::dto::ops::BuildResponse,
        crate::dto::ops::MetricsResponse,
        crate::dto::ops::StatusResponse
    )),
    tags((name = "ops", description = "Operational endpoints"))
)]
pub struct ApiDoc;

pub fn router() -> Router<AppState> {
    let swagger: Router = utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
        .url("/api-doc/openapi.json", ApiDoc::openapi())
        .into();

    // Convert Router<()> -> Router<AppState> so it can be merged.
    swagger.with_state(())
}
