use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub level: EvidenceLevel,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceLevel {
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "MED")]
    Med,
    #[serde(rename = "HIGH")]
    High,
}

impl EvidenceLevel {
    pub fn score(&self) -> u8 {
        match self {
            EvidenceLevel::Low => 1,
            EvidenceLevel::Med => 2,
            EvidenceLevel::High => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigReference {
    pub file_path: String,
    pub hostname: String,
    pub port: Option<u16>,
    pub context: String,
    pub config_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub app_type: String,
    pub version: Option<String>,
    pub listening_ports: Vec<u16>,
    pub config_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundDependency {
    pub source_ip: String,
    pub source_hostname: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<Evidence>,
    pub detection_methods: Vec<String>,
    pub impact_level: ImpactLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDependencyChain {
    pub server_name: String,
    pub outbound_deps: Vec<Dependency>,
    pub inbound_deps: Vec<InboundDependency>,
    pub total_impact: u8,
    pub is_single_point_of_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub connection_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub processes: Vec<String>,
    pub confidence: u8,
    pub evidence: Vec<Evidence>,
    pub config_references: Vec<ConfigReference>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub name: String,
    pub severity: RiskSeverity,
    pub description: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskSeverity {
    #[serde(rename = "INFO")]
    Info,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub observation_window_hours: u32,
    pub total_snapshots: usize,
    pub observation_span: (DateTime<Utc>, DateTime<Utc>),
    pub dependencies: Vec<Dependency>,
    pub inbound_dependencies: Vec<InboundDependency>,
    pub observed_processes: HashMap<String, ProcessActivity>,
    pub risks: Vec<RiskAssessment>,
    pub decommission_confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivity {
    pub name: String,
    pub executions: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub only_once_in_window: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningService {
    pub port: u16,
    pub protocol: String,
    pub process_name: String,
    pub pid: u32,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub cmdline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    pub schedule: String,
    pub command: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdTimer {
    pub name: String,
    pub unit: String,
    pub enabled: bool,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsName {
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationSnapshot {
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub listening_services: Vec<ListeningService>,
    pub network_connections: Vec<NetworkConnection>,
    pub processes: Vec<Process>,
    pub cron_jobs: Vec<CronJob>,
    pub systemd_timers: Vec<SystemdTimer>,
    pub dns_names: Vec<DnsName>,
}
