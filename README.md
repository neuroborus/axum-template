# axum-template

A pragmatic **Axum** service template with a clean baseline for production:

- **OpenAPI + Swagger UI** (code-first, generated from Rust types/handlers)
- **Structured logging** via `tracing` + `tracing-subscriber` (JSON in prod)
- **HTTP request tracing** via `tower-http::TraceLayer`
- **Request ID propagation** (`x-request-id`) end-to-end
- **Baseline middleware** (timeouts, body size limits, compression, concurrency/load shedding)
- **Unified error model** (`thiserror` + `AppError: IntoResponse`)

This template uses an **`ops`** module set:

- `src/dto/ops.rs` — DTOs for ops endpoints
- `src/handlers/ops.rs` — handlers for ops endpoints (`/ops/*`)
- `src/routes/ops.rs` — route wiring for ops endpoints

---

## Quickstart

```bash
cargo install cargo-generate
cargo generate --git https://github.com/neuroborus/axum-template --name my-service

cd my-service
cargo run
```

Run with an explicit log filter:

```bash
RUST_LOG=info,tower_http=info cargo run
```

---

## Docker

Build the image:

```bash
docker build -t my-service .
```

Run the container:

```bash
docker run --rm -p 3000:3000 my-service
```

Override env vars (example):

```bash
docker run --rm -p 8080:8080 \
  -e APP_ENV=production \
  -e LOG_FORMAT=json \
  -e HTTP_PORT=8080 \
  my-service
```

The image includes a minimal HTTP healthcheck client (`wget`) so Docker Compose can probe `/ops/health`.

---

## Docker Compose

Build and run:

```bash
docker compose up --build
```

Check health status:

```bash
docker compose ps
```

Follow logs:

```bash
docker compose logs -f app
```

---

## Agents (AGENTS.md)

This template can optionally generate an `AGENTS.md` file during project creation.
`AGENTS.md` is a lightweight set of working agreements for AI coding agents (and humans) contributing to the repository:
project goals, conventions, and required checks before shipping changes.

### Generation

During `cargo generate`, you will be prompted:

- **Include AGENTS.md?** (`include_agents`)
- **Project goal (AGENTS.md)** (`project_goal`) — the first bullet under “Project goals”.

Examples:

Generate **without** `AGENTS.md`:

```bash
cargo generate --git https://github.com/neuroborus/axum-template --name my-service --define include_agents=false
```

Generate with a custom project goal:

```bash
cargo generate --git https://github.com/neuroborus/axum-template --name my-service \
  --define project_goal="Build a payments API service (Axum + Postgres)."
```

---

## Configuration (Environment variables)

The template reads configuration from environment variables in `src/config.rs`.

### Variables

| Name         | Required | Default       | Allowed values / Notes |
|--------------|----------|---------------|------------------------|
| `HTTP_HOST`  | No       | `127.0.0.1`   | Must be a valid IP address (e.g. `0.0.0.0` to bind on all interfaces). |
| `HTTP_PORT`  | No       | `3000`        | Must be a valid `u16` port. |
| `APP_ENV`    | No       | `development` | `development` (default) or `production` / `prod`. If set to production, JSON logging is forced. |
| `LOG_FORMAT` | No       | `pretty`      | `pretty` (default) or `json`. If `APP_ENV=production`, JSON logging is forced regardless of this value. |
| `APP_CORS_ORIGINS` | No | `""` (disabled) | `""` disables CORS, `*` allows any origin, or a comma-separated allowlist of origins. |
| `APP_RATELIMIT_RPS` | No | (disabled) | Requests per second to allow. If not set, rate limiting is disabled. |
| `APP_RATELIMIT_BURST` | No | `20` | Burst size when rate limiting is enabled. |
| `APP_RATELIMIT_TRUST_PROXY` | No | `false` | If `true`, uses proxy headers (e.g. `X-Forwarded-For`) for client IPs. |

See `.env.example` for a starter config.

Run locally (pretty logs by default):

```bash
HTTP_HOST=127.0.0.1 HTTP_PORT=3000 cargo run
```

Force JSON logs in development:

```bash
APP_ENV=development LOG_FORMAT=json cargo run
```

Run in “production” mode (forces JSON logs):

```bash
APP_ENV=production HTTP_HOST=0.0.0.0 HTTP_PORT=8080 cargo run
```

Enable CORS and rate limiting:

```bash
APP_CORS_ORIGINS="https://example.com,https://admin.example.com" \
APP_RATELIMIT_RPS=50 \
APP_RATELIMIT_BURST=100 \
APP_RATELIMIT_TRUST_PROXY=true \
cargo run
```

Security note: only set `APP_RATELIMIT_TRUST_PROXY=true` when running behind a trusted
reverse proxy that you control; otherwise clients can spoof `X-Forwarded-For` to bypass limits.

Per-route/per-router rate limiting is supported using the same `GovernorLayer` middleware.
Attach it with `.layer(...)` for a whole router or `.route_layer(...)` for a single route.

Example: custom rate limit on a single route:

```rust
use std::sync::Arc;
use axum::{Router, routing::get};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

let health = Router::new().route(
    "/ops/health",
    get(crate::handlers::ops::get_health).route_layer(
        GovernorLayer::new(Arc::new(
    GovernorConfigBuilder::default()
        .per_second(5)
        .burst_size(10)
        .finish()
        .expect("governor config must be valid"),
        )),
    ),
);
```

---

## Default endpoints

- `GET /ops/health` — health check
- `GET /ops/ready` — readiness check
- `GET /ops/metrics` — lightweight JSON metrics (uptime + counters)
- `GET /ops/build` — build metadata (name + version + env)
- `GET /api-doc/openapi.json` — generated OpenAPI spec
- `GET /swagger-ui/` — Swagger UI (interactive docs)

### Ops endpoints

All operational endpoints live under `/ops/*` and return small JSON payloads.
`/ops/metrics` is dependency-free and uses in-memory counters for basic service telemetry.

The app enforces a default request body size limit of 2 MiB via Axum's `DefaultBodyLimit`
for common extractors (e.g. JSON, form, bytes). Override it by adding a different
`DefaultBodyLimit` layer closer to a route or router.

---

## Project layout (as implemented)

This README intentionally reflects the **actual repository tree**.

```
.
├── cargo-generate.toml
├── Cargo.toml
├── README.md
├── .gitignore
└── src
    ├── app.rs
    ├── config.rs
    ├── error.rs
    ├── main.rs
    ├── state.rs
    ├── dto
    │   ├── mod.rs
    │   └── ops.rs
    ├── handlers
    │   ├── mod.rs
    │   └── ops.rs
    └── routes
        ├── mod.rs
        ├── openapi.rs
        └── ops.rs
```

### What each part does

- `src/main.rs` — bootstrap: load config, init logging, build router, bind/listen, graceful shutdown.
- `src/config.rs` — env config + logging mode decision (JSON logs in production).
- `src/app.rs` — router composition + middleware stack (request-id, tracing, timeouts, body limits, compression, concurrency/load shedding).
- `src/state.rs` — shared application state (`AppState`) available to handlers.
- `src/error.rs` — unified error model (`AppError`) implementing `IntoResponse`.
- `src/routes/*` — route wiring (mount points), including:
  - `routes/ops.rs` — ops routes (`/ops/*`)
  - `routes/openapi.rs` — Swagger UI + OpenAPI JSON routes
- `src/handlers/*` — HTTP handlers grouped by area (`ops`).
- `src/dto/*` — request/response DTOs and OpenAPI schemas.

---

## Recommended layers (when the project grows)

This template keeps only the essential layers implemented. If the project grows, it is recommended to introduce the following directories (not present by default):

- `src/domain/` — domain types and invariants (no HTTP/DB concerns)
- `src/services/` — use-cases / orchestration logic (handlers stay thin)
- `src/contracts/` — traits for repos/clients (testability, DI boundaries)
- `src/repositories/` — persistence adapters (DB queries, mapping)
- `src/clients/` — outbound HTTP/RPC clients and SDK integrations
- `src/helpers/` — small focused helpers shared across modules
- `src/utils/` — low-level utilities (keep this lean; prefer domain-specific modules)

---

## Dependencies and why they are included

### Web framework / runtime

- **`axum`** — routing, extractors, responses, and server integration.
- **`tokio`** — async runtime and OS signal handling for graceful shutdown.

Axum feature flags: https://docs.rs/axum/latest/axum/#feature-flags  
Tokio feature flags: https://docs.rs/tokio/latest/tokio/#feature-flags

### Middleware and service composition

- **`tower`** — foundational `Service`/`Layer` abstractions used by Axum and `tower-http`.
  This template uses:
  - `tower::ServiceBuilder` to compose the middleware stack in `src/app.rs`.
  - `tower::util::ServiceExt` (the `util` feature) in tests to execute requests via `.oneshot()` without binding to a TCP port.
  - `ConcurrencyLimitLayer` and `LoadShedLayer` for baseline overload protection.

Tower docs: https://docs.rs/tower/latest/tower/  
Tower features: https://docs.rs/crate/tower/latest/features  
`ServiceExt` docs (requires `util`): https://docs.rs/tower/latest/tower/util/trait.ServiceExt.html

- **`tower-http`** — production-grade HTTP middleware:
  - `TraceLayer` for request spans and response latencies
  - request-id generation and propagation
  - response compression (gzip)
  - timeouts and request body size limits
  - sensitive header marking (avoid leaking auth/cookies into logs)

Feature reference: https://docs.rs/crate/tower-http/latest/features  
Request ID docs: https://docs.rs/tower-http/latest/tower_http/request_id/

### Observability

- **`tracing`** — structured instrumentation (events + spans).
- **`tracing-subscriber`** — formatting and filtering:
  - `RUST_LOG` filtering via `env-filter`
  - JSON logs in production via `json`

Feature reference: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/#crate-feature-flags

### OpenAPI / Swagger UI

- **`utoipa`** — OpenAPI generation from Rust types and handlers (macros).
- **`utoipa-swagger-ui`** — serves Swagger UI and binds it to the generated OpenAPI spec.

Utoipa crate features: https://docs.rs/utoipa/latest/utoipa/#crate-features  
Utoipa Swagger UI crate features: https://docs.rs/utoipa-swagger-ui/latest/utoipa_swagger_ui/#crate-features

### Errors / DTOs

- **`thiserror`** — ergonomic, explicit error enums for a unified `AppError`.
- **`serde`** — DTO serialization/deserialization framework.
- **`serde_json`** — JSON format implementation for `serde` (serialization/deserialization and JSON bodies).
- **`uuid`** — request-id generation and correlation IDs (e.g. internal error IDs).

Serde feature flags: https://serde.rs/feature-flags.html  
UUID feature flags: https://docs.rs/crate/uuid/latest/features

### Test-only utilities

- **`http-body-util`** (dev-dependency) — helpers for collecting HTTP bodies in tests (used via `BodyExt::collect()`).

Docs: https://docs.rs/http-body-util/latest/http_body_util/

---

## Enabled crate features in this template

This template enables specific crate feature flags in `Cargo.toml` (kept explicit to avoid surprises).

### `tokio`

Enabled features:

- `macros`
- `net`
- `rt-multi-thread`
- `signal`

Feature reference: https://docs.rs/tokio/latest/tokio/#feature-flags

### `tower`

Enabled features:

- `limit`
- `load-shed`
- `timeout`
- `util` (test helpers like `.oneshot()`)

Feature reference: https://docs.rs/crate/tower/latest/features

### `tower-http`

Enabled features:

- `compression-gzip`
- `cors`
- `request-id`
- `sensitive-headers`
- `trace`
- `util`
- `cors`

Feature reference: https://docs.rs/crate/tower-http/latest/features  
Request ID docs: https://docs.rs/tower-http/latest/tower_http/request_id/

### `tower-governor`

Enabled features:

- `axum`
- `tracing`

Feature reference: https://docs.rs/crate/tower-governor/latest/features

### `tracing-subscriber`

Enabled features:

- `ansi`
- `env-filter`
- `fmt`
- `json`
- `tracing-log`

Feature reference: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/#crate-feature-flags

### `serde`

Enabled features:

- `derive`
- `std`

Feature reference: https://serde.rs/feature-flags.html

### `uuid`

Enabled features:

- `std`
- `v4`

Feature reference: https://docs.rs/crate/uuid/latest/features

### `utoipa-swagger-ui`

Enabled features:

- `axum`
- `url`

Feature reference: https://docs.rs/utoipa-swagger-ui/latest/utoipa_swagger_ui/#crate-features

---

## Request ID propagation (`x-request-id`)

This template enforces a consistent request ID:

- If the client sends `x-request-id`, it is preserved.
- Otherwise, the server generates one.
- The response includes the same `x-request-id`.

Implementation is based on `tower-http` request-id helpers:
https://docs.rs/tower-http/latest/tower_http/request_id/

---

## Logging

### Local development

Human-readable logs by default. Control verbosity with `RUST_LOG`:

```bash
RUST_LOG=debug,tower_http=debug cargo run
```

### Production

Use JSON logs (recommended for Loki/ELK/Datadog pipelines). This template is designed so production deployments can enforce JSON output by config (for example: `APP_ENV=production`).

Formatting docs:
https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/index.html

### Sensitive data and “secret shadowing”

This template is intentionally conservative:

- `TraceLayer` does **not** include headers by default.
- `SetSensitiveHeadersLayer` marks common sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`) as sensitive.

If you later enable header logging, keep sensitive header filtering enabled and avoid logging request/response bodies that may contain secrets.

---

## Unified error model (`AppError`)

The template uses a single `AppError` enum (in `src/error.rs`) that:

- derives `thiserror::Error`
- implements `IntoResponse`
- returns a consistent JSON error shape (status code + error code + message)

Handlers are expected to return:

```rust
Result<axum::Json<T>, AppError>
```

---

## Testing

This template ships with lightweight router-level tests that do not bind to a TCP port.
They execute requests directly against the Axum `Router` (as a `tower::Service`).

Covered checks:

- `GET /ops/health` returns `200` and `{ "status": "ok" }`
- `x-request-id` is generated if missing
- `x-request-id` is propagated back if provided by the client
- OpenAPI JSON includes the `/ops/health` path
- Swagger UI is served under `/swagger-ui/`
- `AppError` converts to a consistent JSON error response (`IntoResponse`)

### Run tests

> Run tests in a generated project (not in the template repo), since the template `Cargo.toml` contains placeholders.

```bash
cargo test
```

---

## License

MIT
