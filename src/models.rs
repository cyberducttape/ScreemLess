use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeState {
    #[serde(rename = "COMPLETE")]
    Complete,
    #[serde(rename = "PARTIAL")]
    Partial,
    #[serde(rename = "FAILED")]
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeStatus {
    pub state: ProbeState,
    pub details: Option<String>,
    pub unavailable: usize,
}

impl ProbeStatus {
    pub fn complete() -> Self {
        Self {
            state: ProbeState::Complete,
            details: None,
            unavailable: 0,
        }
    }

    pub fn partial(details: impl Into<String>, unavailable: usize) -> Self {
        Self {
            state: ProbeState::Partial,
            details: Some(details.into()),
            unavailable,
        }
    }

    pub fn failed(details: impl Into<String>) -> Self {
        Self {
            state: ProbeState::Failed,
            details: Some(details.into()),
            unavailable: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == ProbeState::Complete
    }
}

impl Default for ProbeStatus {
    fn default() -> Self {
        Self::complete()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProbeStatuses {
    pub network_sockets: ProbeStatus,
    pub process_attribution: ProbeStatus,
    pub cron: ProbeStatus,
    pub systemd: ProbeStatus,
    pub config_scan: ProbeStatus,
    pub dns: ProbeStatus,
}

impl ProbeStatuses {
    pub fn all_complete(&self) -> bool {
        self.network_sockets.is_complete()
            && self.process_attribution.is_complete()
            && self.cron.is_complete()
            && self.systemd.is_complete()
            && self.config_scan.is_complete()
            && self.dns.is_complete()
    }

    pub fn merge(&mut self, other: &Self) {
        Self::merge_status(&mut self.network_sockets, &other.network_sockets);
        Self::merge_status(&mut self.process_attribution, &other.process_attribution);
        Self::merge_status(&mut self.cron, &other.cron);
        Self::merge_status(&mut self.systemd, &other.systemd);
        Self::merge_status(&mut self.config_scan, &other.config_scan);
        Self::merge_status(&mut self.dns, &other.dns);
    }

    fn merge_status(current: &mut ProbeStatus, other: &ProbeStatus) {
        let rank = |state: &ProbeState| match state {
            ProbeState::Complete => 0,
            ProbeState::Partial => 1,
            ProbeState::Failed => 2,
        };
        if rank(&other.state) > rank(&current.state) {
            *current = other.clone();
        } else if rank(&other.state) == rank(&current.state) {
            current.unavailable += other.unavailable;
            if current.details.is_none() {
                current.details = other.details.clone();
            }
        }
    }
}

impl ProbeStatuses {
    pub fn legacy_unknown() -> Self {
        let unknown = || ProbeStatus::failed("probe status unavailable for this snapshot");
        Self {
            network_sockets: unknown(),
            process_attribution: unknown(),
            cron: unknown(),
            systemd: unknown(),
            config_scan: unknown(),
            dns: unknown(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub level: EvidenceLevel,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    #[serde(alias = "is_single_point_of_failure")]
    pub is_high_fan_in: bool,
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
    #[serde(default)]
    pub host_identity: HostIdentity,
    #[serde(default)]
    pub coverage: ObservationCoverage,
    pub dependencies: Vec<Dependency>,
    pub inbound_dependencies: Vec<InboundDependency>,
    pub observed_processes: HashMap<String, ProcessActivity>,
    pub risks: Vec<RiskAssessment>,
    pub decommission_confidence: u8,
    #[serde(default)]
    pub probe_statuses: ProbeStatuses,
    #[serde(default)]
    pub inventory: SiteInventory,
}

/// Describes how much of the requested observation window was actually
/// observed and which collection probes produced usable evidence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservationCoverage {
    pub requested_window_hours: u32,
    pub actual_span_seconds: i64,
    pub expected_samples: usize,
    pub successful_samples: usize,
    pub coverage_percent: f64,
    pub last_observation: Option<DateTime<Utc>>,
    pub probe_coverage: HashMap<String, f64>,
    pub privileges: String,
    pub evidence_quality: String,
    pub remaining_unknowns: Vec<String>,
}

/// A server-side inventory derived from the same snapshots used for dependency analysis.
/// Values are observations or conservative inferences; they are not claims from an
/// external CMS, analytics platform, or cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteInventory {
    pub websites: Vec<WebsiteInventory>,
    pub users: Vec<String>,
    pub databases: Vec<InventoryConnection>,
    pub storage_connections: Vec<InventoryConnection>,
    pub tech_stack: Vec<String>,
    #[serde(default)]
    pub software: Vec<SoftwareInventory>,
    pub load_balancers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInventory {
    pub name: String,
    pub version: Option<String>,
    pub executable: Option<String>,
    pub evidence: String,
    pub observations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebsiteInventory {
    pub name: String,
    pub status: String,
    pub ports: Vec<u16>,
    #[serde(alias = "usage_observations")]
    pub availability_observations: usize,
    #[serde(default)]
    pub inbound_connection_observations: usize,
    pub content_paths: Vec<String>,
    pub tech_stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryConnection {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub usage_observations: usize,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivity {
    pub name: String,
    #[serde(default, alias = "executions")]
    pub observed_snapshots: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default, alias = "only_once_in_window")]
    pub observed_once_in_window: bool,
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
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub active: Option<bool>,
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
    #[serde(default)]
    pub host_identity: HostIdentity,
    pub listening_services: Vec<ListeningService>,
    pub network_connections: Vec<NetworkConnection>,
    pub processes: Vec<Process>,
    pub cron_jobs: Vec<CronJob>,
    pub systemd_timers: Vec<SystemdTimer>,
    pub dns_names: Vec<DnsName>,
    #[serde(default)]
    pub config_references: Vec<ConfigReference>,
    #[serde(default)]
    pub software: Vec<SoftwareInventory>,
    #[serde(default)]
    pub sampling_interval_seconds: Option<u64>,
    #[serde(default = "unknown_privileges")]
    pub privileges: String,
    #[serde(default = "ProbeStatuses::legacy_unknown")]
    pub probe_statuses: ProbeStatuses,
}

/// Stable local identity and address inventory used to correlate raw socket
/// addresses with the machine that owns them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostIdentity {
    pub hostname: String,
    pub fqdn: Option<String>,
    pub short_hostname: String,
    pub host_uuid: Option<String>,
    pub machine_id: Option<String>,
    pub cloud_instance_id: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub vip_addresses: Vec<String>,
    pub interface_addresses: Vec<String>,
    pub dns_aliases: Vec<String>,
    pub container_addresses: Vec<String>,
}

fn unknown_privileges() -> String {
    "unknown".to_string()
}
