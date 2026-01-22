use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnvDto {
    Development,
    Production,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusResponse {
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetricsResponse {
    pub uptime_seconds: u64,
    pub requests_total: u64,
    pub responses_total: u64,
    pub responses_2xx: u64,
    pub responses_4xx: u64,
    pub responses_5xx: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildResponse {
    pub name: String,
    pub version: String,
    pub env: EnvDto,
}
