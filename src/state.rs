use crate::config::Settings;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub metrics: Arc<MetricsState>,
}

impl AppState {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings: Arc::new(settings),
            metrics: Arc::new(MetricsState::new()),
        }
    }
}

pub struct MetricsState {
    start_time: Instant,
    requests_total: AtomicU64,
    responses_total: AtomicU64,
    responses_2xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
}

pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub requests_total: u64,
    pub responses_total: u64,
    pub responses_2xx: u64,
    pub responses_4xx: u64,
    pub responses_5xx: u64,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            requests_total: AtomicU64::new(0),
            responses_total: AtomicU64::new(0),
            responses_2xx: AtomicU64::new(0),
            responses_4xx: AtomicU64::new(0),
            responses_5xx: AtomicU64::new(0),
        }
    }

    pub fn on_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_response(&self, status: axum::http::StatusCode) {
        self.responses_total.fetch_add(1, Ordering::Relaxed);

        if status.is_success() {
            self.responses_2xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_client_error() {
            self.responses_4xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_server_error() {
            self.responses_5xx.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_seconds: self.start_time.elapsed().as_secs(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            responses_total: self.responses_total.load(Ordering::Relaxed),
            responses_2xx: self.responses_2xx.load(Ordering::Relaxed),
            responses_4xx: self.responses_4xx.load(Ordering::Relaxed),
            responses_5xx: self.responses_5xx.load(Ordering::Relaxed),
        }
    }
}
