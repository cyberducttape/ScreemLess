use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};

use crate::db::Database;
use crate::models::*;
use crate::config_scanner::ConfigScanner;

pub struct Analyzer<'a> {
    db: &'a Database,
}

impl<'a> Analyzer<'a> {
    pub fn new(db: &'a Database) -> Self {
        Analyzer { db }
    }

    pub fn analyze(&self, hostname: &str, hours: u32) -> Result<AnalysisResult> {
        let now = Utc::now();
        let since = now - Duration::hours(hours as i64);

        let snapshots = self.db.get_snapshots_since(hostname, since.timestamp())?;

        if snapshots.is_empty() {
            return Ok(AnalysisResult {
                observation_window_hours: hours,
                total_snapshots: 0,
                observation_span: (now, now),
                dependencies: Vec::new(),
                observed_processes: HashMap::new(),
                risks: Vec::new(),
                decommission_confidence: 0,
            });
        }

        let first_snap = snapshots.first().unwrap();
        let last_snap = snapshots.last().unwrap();

        let dependencies = self.infer_dependencies(&snapshots)?;
        let observed_processes = self.analyze_process_activity(&snapshots)?;
        let risks = self.assess_risks(&snapshots, &dependencies, &observed_processes)?;
        let decommission_confidence = self.calculate_decommission_confidence(
            &snapshots,
            &dependencies,
            &observed_processes,
        );

        Ok(AnalysisResult {
            observation_window_hours: hours,
            total_snapshots: snapshots.len(),
            observation_span: (first_snap.timestamp, last_snap.timestamp),
            dependencies,
            observed_processes,
            risks,
            decommission_confidence,
        })
    }

    fn infer_dependencies(&self, snapshots: &[ObservationSnapshot]) -> Result<Vec<Dependency>> {
        let mut remote_hosts: HashMap<(String, u16), Vec<(DateTime<Utc>, HashSet<String>)>> =
            HashMap::new();

        for snapshot in snapshots {
            for conn in &snapshot.network_connections {
                let key = (conn.remote_addr.clone(), conn.remote_port);
                let mut processes = HashSet::new();
                processes.insert(conn.process_name.clone());

                remote_hosts
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push((snapshot.timestamp, processes));
            }
        }

        let config_refs = ConfigScanner::scan().unwrap_or_default();
        let ip_to_hostname = self.build_ip_to_hostname_map(snapshots);

        let mut dependencies = Vec::new();

        for ((remote_addr, remote_port), observations) in remote_hosts {
            let connection_count = observations.len();

            let mut all_processes = HashSet::new();
            for (_ts, procs) in &observations {
                all_processes.extend(procs.clone());
            }

            let first_seen = observations.iter().map(|(ts, _)| *ts).min().unwrap();
            let last_seen = observations.iter().map(|(ts, _)| *ts).max().unwrap();

            let mut evidence = Vec::new();

            if connection_count > 100 {
                evidence.push(Evidence {
                    level: EvidenceLevel::High,
                    description: format!("{} observed connections", connection_count),
                });
            } else if connection_count > 10 {
                evidence.push(Evidence {
                    level: EvidenceLevel::Med,
                    description: format!("{} observed connections", connection_count),
                });
            } else {
                evidence.push(Evidence {
                    level: EvidenceLevel::Low,
                    description: format!("{} observed connections", connection_count),
                });
            }

            if all_processes.len() == 1 {
                evidence.push(Evidence {
                    level: EvidenceLevel::High,
                    description: format!(
                        "Consistent process: {}",
                        all_processes.iter().next().unwrap()
                    ),
                });
            }

            let config_references = config_refs
                .iter()
                .filter(|cr| {
                    (cr.hostname == remote_addr || cr.port == Some(remote_port))
                        || cr.hostname.split('.').last() == remote_addr.split('.').last()
                })
                .cloned()
                .collect::<Vec<_>>();

            if !config_references.is_empty() {
                evidence.push(Evidence {
                    level: EvidenceLevel::Med,
                    description: format!("Found in {} config files", config_references.len()),
                });
            }

            let hostname = ip_to_hostname.get(&remote_addr).cloned();
            if hostname.is_some() {
                evidence.push(Evidence {
                    level: EvidenceLevel::Med,
                    description: "Resolved hostname from DNS".to_string(),
                });
            }

            let confidence = Self::calculate_confidence(&evidence);

            dependencies.push(Dependency {
                remote_addr,
                remote_port,
                protocol: "tcp".to_string(),
                connection_count,
                first_seen,
                last_seen,
                processes: all_processes.into_iter().collect(),
                confidence,
                evidence,
                config_references,
                hostname,
            });
        }

        dependencies.sort_by(|a, b| b.connection_count.cmp(&a.connection_count));
        Ok(dependencies)
    }

    fn analyze_process_activity(
        &self,
        snapshots: &[ObservationSnapshot],
    ) -> Result<HashMap<String, ProcessActivity>> {
        let mut process_appearances: HashMap<String, Vec<DateTime<Utc>>> = HashMap::new();

        for snapshot in snapshots {
            for process in &snapshot.processes {
                process_appearances
                    .entry(process.name.clone())
                    .or_insert_with(Vec::new)
                    .push(snapshot.timestamp);
            }
        }

        let mut result = HashMap::new();

        for (name, mut appearances) in process_appearances {
            appearances.sort();
            appearances.dedup();

            let executions = appearances.len();
            let first_seen = appearances.first().cloned().unwrap_or_else(Utc::now);
            let last_seen = appearances.last().cloned().unwrap_or_else(Utc::now);

            let only_once = executions == 1;

            result.insert(
                name.clone(),
                ProcessActivity {
                    name,
                    executions,
                    first_seen,
                    last_seen,
                    only_once_in_window: only_once,
                },
            );
        }

        Ok(result)
    }

    fn assess_risks(
        &self,
        snapshots: &[ObservationSnapshot],
        dependencies: &[Dependency],
        observed_processes: &HashMap<String, ProcessActivity>,
    ) -> Result<Vec<RiskAssessment>> {
        let mut risks = Vec::new();

        let has_listeners = snapshots.iter().any(|s| !s.listening_services.is_empty());
        if has_listeners {
            risks.push(RiskAssessment {
                name: "Active listening services".to_string(),
                severity: RiskSeverity::Warn,
                description: "Server is listening on ports (likely has inbound dependencies)".to_string(),
                evidence: "Listening services detected in observations".to_string(),
            });
        }

        for dep in dependencies {
            if dep.connection_count == 1 {
                risks.push(RiskAssessment {
                    name: "One-time connection".to_string(),
                    severity: RiskSeverity::Info,
                    description: format!("Connection to {}:{} observed only once", dep.remote_addr, dep.remote_port),
                    evidence: "Single observation of this connection in window".to_string(),
                });
            }
        }

        for proc in observed_processes.values() {
            if proc.only_once_in_window && (proc.name.contains("backup") || proc.name.contains("sync") || proc.name.contains("update")) {
                risks.push(RiskAssessment {
                    name: "Critical process seen once".to_string(),
                    severity: RiskSeverity::Warn,
                    description: format!("Process '{}' appeared only once in observation window", proc.name),
                    evidence: format!("Last seen {}", proc.last_seen.format("%Y-%m-%d %H:%M:%S UTC")),
                });
            }
        }

        let has_cron = snapshots.iter().any(|s| !s.cron_jobs.is_empty());
        if has_cron {
            risks.push(RiskAssessment {
                name: "Scheduled jobs present".to_string(),
                severity: RiskSeverity::Warn,
                description: "Cron jobs or timers are configured on this server".to_string(),
                evidence: "Cron jobs found in /etc/cron.d and related directories".to_string(),
            });
        }

        risks.sort_by(|a, b| match (&a.severity, &b.severity) {
            (RiskSeverity::Fail, _) => std::cmp::Ordering::Less,
            (_, RiskSeverity::Fail) => std::cmp::Ordering::Greater,
            (RiskSeverity::Warn, RiskSeverity::Info) => std::cmp::Ordering::Less,
            (RiskSeverity::Info, RiskSeverity::Warn) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        });

        Ok(risks)
    }

    fn calculate_confidence(evidence: &[Evidence]) -> u8 {
        if evidence.is_empty() {
            return 0;
        }

        let total_score: u8 = evidence.iter().map(|e| e.level.score()).sum();
        let max_score = (evidence.len() as u8) * 3;

        ((total_score as u16 * 100) / max_score as u16) as u8
    }

    fn build_ip_to_hostname_map(&self, snapshots: &[ObservationSnapshot]) -> HashMap<String, String> {
        let mut map = HashMap::new();

        for snapshot in snapshots {
            for dns in &snapshot.dns_names {
                for ip in &dns.ip_addresses {
                    map.insert(ip.clone(), dns.hostname.clone());
                }
            }
        }

        map
    }

    fn calculate_decommission_confidence(
        &self,
        snapshots: &[ObservationSnapshot],
        dependencies: &[Dependency],
        observed_processes: &HashMap<String, ProcessActivity>,
    ) -> u8 {
        let mut score = 100u16;

        let has_listeners = snapshots.iter().any(|s| !s.listening_services.is_empty());
        if has_listeners {
            score = score.saturating_sub(40);
        }

        if !dependencies.is_empty() {
            let high_confidence_deps = dependencies.iter().filter(|d| d.confidence >= 70).count();
            if high_confidence_deps > 0 {
                score = score.saturating_sub((high_confidence_deps as u16) * 15);
            }
        }

        let one_time_critical = observed_processes
            .values()
            .filter(|p| {
                p.only_once_in_window
                    && (p.name.contains("backup") || p.name.contains("sync"))
            })
            .count();

        if one_time_critical > 0 {
            score = score.saturating_sub((one_time_critical as u16) * 10);
        }

        let has_cron = !snapshots.iter().all(|s| s.cron_jobs.is_empty());
        if has_cron {
            score = score.saturating_sub(20);
        }

        score.min(100) as u8
    }
}
