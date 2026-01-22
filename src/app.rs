use axum::{
    BoxError, Router,
    body::Body,
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    extract::State,
    http::{
        Request,
        header::{AUTHORIZATION, COOKIE, SET_COOKIE},
    },
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower::{limit::ConcurrencyLimitLayer, load_shed::LoadShedLayer, timeout::TimeoutLayer};
use tower_governor::{
    GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor},
};
use tower_http::{
    LatencyUnit, ServiceBuilderExt,
    compression::CompressionLayer,
    cors::{AllowOrigin, Any, CorsLayer},
    request_id::MakeRequestUuid,
    sensitive_headers::SetSensitiveHeadersLayer,
    trace::{DefaultOnResponse, TraceLayer},
};

use crate::config::{CorsConfig, Settings};
use crate::error::AppError;
use crate::state::AppState;

const DEFAULT_BODY_LIMIT: usize = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONCURRENCY_LIMIT: usize = 256;

pub fn build_router(state: AppState) -> Router<()> {
    let routes = crate::routes::router();
    let settings = state.settings.clone();

    let middleware = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_middleware_error))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<_>| {
                    let request_id = req
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();

                    tracing::info_span!(
                        "request",
                        request_id = %request_id,
                        method = %req.method(),
                        uri = %req.uri(),
                    )
                })
                .on_response(DefaultOnResponse::new().latency_unit(LatencyUnit::Micros)),
        )
        .layer(ConcurrencyLimitLayer::new(DEFAULT_CONCURRENCY_LIMIT))
        .layer(LoadShedLayer::new())
        .layer(CompressionLayer::new())
        .layer(SetSensitiveHeadersLayer::new([
            AUTHORIZATION,
            COOKIE,
            SET_COOKIE,
        ]))
        .layer(TimeoutLayer::new(DEFAULT_TIMEOUT));

    let request_id_middleware = ServiceBuilder::new()
        .set_x_request_id(MakeRequestUuid)
        .propagate_x_request_id();

    let app = Router::<AppState>::new().merge(routes).layer(middleware);
    let app = app.layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT));
    let app = apply_cors(app, settings.as_ref());
    let app = apply_ratelimit(app, settings.as_ref());
    let app = app.layer(from_fn_with_state(state.clone(), track_metrics));
    let app = app.layer(request_id_middleware);
    app.with_state(state)
}

async fn handle_middleware_error(err: BoxError) -> Response {
    if err.is::<tower::load_shed::error::Overloaded>() {
        return AppError::service_unavailable().into_response();
    }

    if err.is::<tower::timeout::error::Elapsed>() {
        return AppError::timeout().into_response();
    }

    tracing::error!(error = %err, "Unhandled middleware error");
    AppError::internal().into_response()
}

fn apply_cors(app: Router<AppState>, settings: &Settings) -> Router<AppState> {
    match &settings.cors {
        CorsConfig::Disabled => app,
        CorsConfig::Any => app.layer(CorsLayer::new().allow_origin(Any)),
        CorsConfig::AllowList(origins) => {
            app.layer(CorsLayer::new().allow_origin(AllowOrigin::list(origins.clone())))
        }
    }
}

fn apply_ratelimit(app: Router<AppState>, settings: &Settings) -> Router<AppState> {
    let Some(ratelimit) = settings.ratelimit.as_ref() else {
        return app;
    };

    if ratelimit.trust_proxy {
        let governor_config = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(u64::from(ratelimit.rps.get()))
                .burst_size(ratelimit.burst.get())
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .expect("governor config must be valid"),
        );
        app.layer(GovernorLayer::new(governor_config))
    } else {
        let governor_config = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(u64::from(ratelimit.rps.get()))
                .burst_size(ratelimit.burst.get())
                .key_extractor(PeerIpKeyExtractor)
                .finish()
                .expect("governor config must be valid"),
        );
        app.layer(GovernorLayer::new(governor_config))
    }
}

async fn track_metrics(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    state.metrics.on_request();
    let response = next.run(req).await;
    state.metrics.on_response(response.status());
    response
}

#[cfg(test)]
mod tests {
    use super::build_router;

    use axum::{
        body::{Body, Bytes},
        extract::DefaultBodyLimit,
        http::{Request, StatusCode, header},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::sync::Arc;
    use tokio::sync::{Mutex, oneshot};
    use tower::util::ServiceExt;
    use tower_http::{ServiceBuilderExt, request_id::MakeRequestUuid};

    use crate::config::{AppEnv, CorsConfig, LogFormat, Settings};
    use crate::state::AppState;

    fn test_settings() -> Settings {
        Settings {
            http_host: "127.0.0.1".parse().unwrap(),
            http_port: 0,
            app_env: AppEnv::Development,
            log_format: LogFormat::Pretty,
            cors: CorsConfig::Disabled,
            ratelimit: None,
        }
    }

    fn test_app() -> axum::Router<()> {
        let state = AppState::new(test_settings());
        build_router(state)
    }

    async fn body_to_bytes(res: Response) -> Bytes {
        res.into_body()
            .collect()
            .await
            .expect("body collect must succeed")
            .to_bytes()
    }

    #[tokio::test]
    async fn health_returns_200_and_status_ok() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/ops/health")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = body_to_bytes(res).await;
        let json: Value = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn ready_returns_200_and_status_ok() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/ops/ready")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = body_to_bytes(res).await;
        let json: Value = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn build_returns_name_and_version() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/ops/build")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = body_to_bytes(res).await;
        let json: Value = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(json["name"], env!("CARGO_PKG_NAME"));
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["env"], "development");
    }

    #[tokio::test]
    async fn metrics_counts_requests_and_responses() {
        let app = test_app();

        for path in ["/ops/health", "/ops/ready"] {
            let req = Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        let req = Request::builder()
            .method("GET")
            .uri("/ops/metrics")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = body_to_bytes(res).await;
        let json: Value = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(json["requests_total"], 3);
        assert_eq!(json["responses_total"], 2);
        assert_eq!(json["responses_2xx"], 2);
    }

    #[tokio::test]
    async fn request_id_is_generated_when_missing() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/ops/health")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        let rid = res
            .headers()
            .get("x-request-id")
            .expect("x-request-id must be present")
            .to_str()
            .unwrap();

        assert!(!rid.is_empty(), "x-request-id must not be empty");
    }

    #[tokio::test]
    async fn request_id_is_propagated_when_provided() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/ops/health")
            .header("x-request-id", "test-123")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        let rid = res
            .headers()
            .get("x-request-id")
            .expect("x-request-id must be present")
            .to_str()
            .unwrap();

        assert_eq!(rid, "test-123");
    }

    #[tokio::test]
    async fn openapi_contains_health_path() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/api-doc/openapi.json")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = body_to_bytes(res).await;
        let json: Value = serde_json::from_slice(bytes.as_ref()).unwrap();

        assert!(
            json["paths"]["/ops/health"].is_object(),
            "OpenAPI must include /ops/health"
        );
    }

    #[tokio::test]
    async fn swagger_ui_is_served() {
        let app = test_app();

        let req = Request::builder()
            .method("GET")
            .uri("/swagger-ui/")
            .header(header::ACCEPT, "text/html")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = body_to_bytes(res).await;
        let html = String::from_utf8_lossy(&bytes);

        assert!(
            html.to_lowercase().contains("swagger"),
            "Swagger UI HTML must contain 'swagger'"
        );
    }

    #[tokio::test]
    async fn app_error_bad_request_converts_to_json_response() {
        use axum::http::header::CONTENT_TYPE;

        let res = crate::error::AppError::bad_request("nope").into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let content_type = res
            .headers()
            .get(CONTENT_TYPE)
            .expect("content-type must be present")
            .to_str()
            .unwrap();

        assert!(
            content_type.starts_with("application/json"),
            "content-type must be application/json"
        );

        let bytes = body_to_bytes(res).await;
        let json: Value = serde_json::from_slice(bytes.as_ref()).unwrap();

        let body_str = json.to_string();
        assert!(body_str.contains("nope"), "error body must include message");
    }

    #[tokio::test]
    async fn app_error_internal_converts_to_500() {
        let res = crate::error::AppError::internal().into_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn body_limit_rejects_large_payload_and_has_request_id() {
        async fn accept_bytes(_: Bytes) -> &'static str {
            "ok"
        }

        let app = axum::Router::new()
            .route("/body", post(accept_bytes))
            .layer(DefaultBodyLimit::max(8))
            .layer(
                tower::ServiceBuilder::new()
                    .set_x_request_id(MakeRequestUuid)
                    .propagate_x_request_id(),
            );

        let req = Request::builder()
            .method("POST")
            .uri("/body")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from("0123456789"))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(res.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn timeout_returns_gateway_timeout_and_has_request_id() {
        async fn slow() -> &'static str {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            "ok"
        }

        let app = axum::Router::new()
            .route("/slow", get(slow))
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::error_handling::HandleErrorLayer::new(
                        super::handle_middleware_error,
                    ))
                    .layer(tower::timeout::TimeoutLayer::new(
                        std::time::Duration::from_millis(2),
                    )),
            )
            .layer(
                tower::ServiceBuilder::new()
                    .set_x_request_id(MakeRequestUuid)
                    .propagate_x_request_id(),
            );

        let req = Request::builder()
            .method("GET")
            .uri("/slow")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(res.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn load_shed_rejects_when_concurrency_exceeded() {
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let release_rx = Arc::new(Mutex::new(Some(release_rx)));

        let app = axum::Router::new()
            .route(
                "/blocked",
                get({
                    let started_tx = Arc::clone(&started_tx);
                    let release_rx = Arc::clone(&release_rx);
                    move || {
                        let started_tx = Arc::clone(&started_tx);
                        let release_rx = Arc::clone(&release_rx);
                        async move {
                            if let Some(rx) = release_rx.lock().await.take() {
                                if let Some(tx) = started_tx.lock().await.take() {
                                    let _ = tx.send(());
                                }
                                let _ = rx.await;
                            }
                            "ok"
                        }
                    }
                }),
            )
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::error_handling::HandleErrorLayer::new(
                        super::handle_middleware_error,
                    ))
                    .layer(tower::load_shed::LoadShedLayer::new())
                    .layer(tower::limit::GlobalConcurrencyLimitLayer::with_semaphore(
                        semaphore,
                    )),
            )
            .layer(
                tower::ServiceBuilder::new()
                    .set_x_request_id(MakeRequestUuid)
                    .propagate_x_request_id(),
            );

        let req1 = Request::builder()
            .method("GET")
            .uri("/blocked")
            .body(Body::empty())
            .unwrap();
        let req2 = Request::builder()
            .method("GET")
            .uri("/blocked")
            .body(Body::empty())
            .unwrap();

        let app_clone = app.clone();
        let fut1 = tokio::spawn(async move { app_clone.oneshot(req1).await.unwrap() });

        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), started_rx)
            .await
            .expect("blocked handler should start");

        let res2 = app.oneshot(req2).await.unwrap();
        let _ = release_tx.send(());
        let res1 = fut1.await.unwrap();

        let statuses = [res1.status(), res2.status()];
        assert!(statuses.contains(&StatusCode::OK));
        assert!(statuses.contains(&StatusCode::SERVICE_UNAVAILABLE));
        assert!(res1.headers().contains_key("x-request-id"));
        assert!(res2.headers().contains_key("x-request-id"));
    }
}
