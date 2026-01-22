use axum::Router;

use crate::state::AppState;

mod openapi;
mod ops;

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .nest("/ops", ops::router())
        .merge(openapi::router())
}
