use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};

use crate::db::Database;
use crate::models::*;

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
                inbound_dependencies: Vec::new(),
                observed_processes: HashMap::new(),
                risks: Vec::new(),
                decommission_confidence: 0,
                probe_statuses: ProbeStatuses::default(),
            });
        }

        let mut probe_statuses = ProbeStatuses::default();
        for snapshot in &snapshots {
            probe_statuses.merge(&snapshot.probe_statuses);
        }

        let first_snap = snapshots.first().unwrap();
        let last_snap = snapshots.last().unwrap();

        let dependencies = self.infer_dependencies(&snapshots)?;
        let observed_processes = self.analyze_process_activity(&snapshots)?;

        let inbound_dependencies = self.infer_inbound_dependencies(hostname, since.timestamp())?;

        let mut risks = self.assess_risks(
            &snapshots,
            &dependencies,
            &inbound_dependencies,
            &observed_processes,
        )?;
        let mut decommission_confidence = self.calculate_decommission_confidence(
            &snapshots,
            &dependencies,
            &inbound_dependencies,
            &observed_processes,
        );
        if !probe_statuses.all_complete() {
            risks.push(RiskAssessment {
                name: "Incomplete observation data".to_string(),
                severity: RiskSeverity::Fail,
                description: "One or more collection probes failed or had incomplete attribution".to_string(),
                evidence: Self::probe_status_summary(&probe_statuses),
            });
            decommission_confidence = decommission_confidence.min(49);
        }

        Ok(AnalysisResult {
            observation_window_hours: hours,
            total_snapshots: snapshots.len(),
            observation_span: (first_snap.timestamp, last_snap.timestamp),
            dependencies,
            inbound_dependencies,
            observed_processes,
            risks,
            decommission_confidence,
            probe_statuses,
        })
    }

    fn probe_status_summary(statuses: &ProbeStatuses) -> String {
        let mut incomplete = Vec::new();
        for (name, status) in [
            ("network_sockets", &statuses.network_sockets),
            ("process_attribution", &statuses.process_attribution),
            ("cron", &statuses.cron),
            ("systemd", &statuses.systemd),
            ("config_scan", &statuses.config_scan),
            ("dns", &statuses.dns),
        ] {
            if !status.is_complete() {
                incomplete.push(format!("{}: {:?}", name, status.state));
            }
        }
        incomplete.join(", ")
    }

    fn infer_inbound_dependencies(
        &self,
        target_hostname: &str,
        since_timestamp: i64,
    ) -> Result<Vec<InboundDependency>> {
        #[derive(Default)]
        struct SourceEvidence {
            count: usize,
            ports: HashSet<u16>,
            processes: HashSet<String>,
            complete: bool,
        }

        let snapshots = self.db.get_all_snapshots_since(since_timestamp)?;
        let target = target_hostname.to_ascii_lowercase();
        let mut sources: HashMap<String, SourceEvidence> = HashMap::new();

        for snapshot in snapshots {
            let source = snapshot.hostname.clone();
            if source.eq_ignore_ascii_case(target_hostname) {
                continue;
            }

            let target_ips = snapshot.dns_names.iter()
                .filter(|dns| dns.hostname.eq_ignore_ascii_case(target_hostname))
                .flat_map(|dns| dns.ip_addresses.iter().cloned())
                .collect::<HashSet<_>>();

            for connection in snapshot.network_connections.iter().filter(|connection| {
                connection.remote_addr.eq_ignore_ascii_case(&target)
                    || target_ips.contains(&connection.remote_addr)
            }) {
                let evidence = sources.entry(source.clone()).or_insert_with(|| SourceEvidence {
                    complete: true,
                    ..SourceEvidence::default()
                });
                evidence.count += 1;
                evidence.ports.insert(connection.remote_port);
                evidence.processes.insert(connection.process_name.clone());
                evidence.complete &= snapshot.probe_statuses.network_sockets.is_complete();
            }
        }

        let mut inbound = Vec::new();
        for (source, evidence) in sources {
            let confidence = (55 + evidence.count.min(9) * 5).min(100) as u8;
            let confidence = if evidence.complete { confidence } else { confidence.min(69) };
            let port_list = evidence.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
            let process_list = evidence.processes.iter().cloned().collect::<Vec<_>>().join(", ");

            inbound.push(InboundDependency {
                source_ip: "unknown".to_string(),
                source_hostname: Some(source),
                confidence,
                evidence: vec![Evidence {
                    level: if confidence >= 70 { EvidenceLevel::High } else { EvidenceLevel::Med },
                    description: format!(
                        "Observed outbound TCP traffic to this server on port(s) {} ({} observation(s), process(es): {})",
                        port_list, evidence.count, process_list
                    ),
                }],
                detection_methods: vec!["central_outbound_observation".to_string()],
                impact_level: if confidence >= 85 { ImpactLevel::High } else { ImpactLevel::Medium },
            });
        }

        inbound.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        Ok(inbound)
    }

    fn infer_dependencies(&self, snapshots: &[ObservationSnapshot]) -> Result<Vec<Dependency>> {
        let mut remote_hosts: HashMap<(String, u16, String), Vec<(DateTime<Utc>, HashSet<String>)>> =
            HashMap::new();

        for snapshot in snapshots {
            for conn in &snapshot.network_connections {
                let key = (conn.remote_addr.clone(), conn.remote_port, conn.protocol.clone());
                let mut processes = HashSet::new();
                processes.insert(conn.process_name.clone());

                remote_hosts
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push((snapshot.timestamp, processes));
            }
        }

        let config_refs = snapshots
            .iter()
            .flat_map(|snapshot| snapshot.config_references.iter().cloned())
            .collect::<Vec<_>>();
        let ip_to_hostname = self.build_ip_to_hostname_map(snapshots);

        let mut dependencies = Vec::new();

        for ((remote_addr, remote_port, protocol), observations) in remote_hosts {
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

            let hostname = ip_to_hostname.get(&remote_addr).cloned();
            let config_references = config_refs
                .iter()
                .filter(|cr| {
                    let hostname_matches = cr.hostname.eq_ignore_ascii_case(&remote_addr)
                        || hostname.as_ref()
                            .is_some_and(|resolved| cr.hostname.eq_ignore_ascii_case(resolved));
                    let port_matches = cr.port.is_none() || cr.port == Some(remote_port);
                    hostname_matches && port_matches
                })
                .cloned()
                .collect::<Vec<_>>();

            if !config_references.is_empty() {
                evidence.push(Evidence {
                    level: EvidenceLevel::Med,
                    description: format!("Found in {} config files", config_references.len()),
                });
            }

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
                protocol,
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

            let observed_snapshots = appearances.len();
            let first_seen = appearances.first().cloned().unwrap_or_else(Utc::now);
            let last_seen = appearances.last().cloned().unwrap_or_else(Utc::now);

            let observed_once = observed_snapshots == 1;

            result.insert(
                name.clone(),
                ProcessActivity {
                    name,
                    observed_snapshots,
                    first_seen,
                    last_seen,
                    observed_once_in_window: observed_once,
                },
            );
        }

        Ok(result)
    }

    fn assess_risks(
        &self,
        snapshots: &[ObservationSnapshot],
        dependencies: &[Dependency],
        inbound_dependencies: &[InboundDependency],
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

        for inbound in inbound_dependencies {
            let source = inbound.source_hostname.as_deref().unwrap_or(&inbound.source_ip);
            risks.push(RiskAssessment {
                name: "Confirmed inbound dependency".to_string(),
                severity: if inbound.confidence >= 70 {
                    RiskSeverity::Fail
                } else {
                    RiskSeverity::Warn
                },
                description: format!(
                    "{} depends on this server ({}% confidence)",
                    source, inbound.confidence
                ),
                evidence: inbound.evidence.iter()
                    .map(|evidence| evidence.description.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
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
            if proc.observed_once_in_window && (proc.name.contains("backup") || proc.name.contains("sync") || proc.name.contains("update")) {
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

        let total_score: u16 = evidence.iter().map(|e| u16::from(e.level.score())).sum();
        let max_score = (evidence.len() as u16) * 3;

        ((total_score * 100) / max_score) as u8
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
        inbound_dependencies: &[InboundDependency],
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

        if !inbound_dependencies.is_empty() {
            let confirmed = inbound_dependencies
                .iter()
                .filter(|dependency| dependency.confidence >= 70)
                .count();
            if confirmed > 0 {
                score = score.saturating_sub(50 + (confirmed as u16) * 20);
            } else {
                score = score.saturating_sub(30);
            }
        }

        let one_time_critical = observed_processes
            .values()
            .filter(|p| {
                p.observed_once_in_window
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

#[cfg(test)]
mod tests {
    use super::Analyzer;
    use crate::db::Database;
    use crate::models::{ImpactLevel, InboundDependency};

    #[test]
    fn confirmed_inbound_dependency_blocks_high_readiness() {
        let path = std::env::temp_dir().join(format!(
            "screamless-analysis-test-{}.db",
            std::process::id()
        ));
        let db = Database::new(&path).unwrap();
        let analyzer = Analyzer::new(&db);
        let inbound = vec![InboundDependency {
            source_ip: "unknown".to_string(),
            source_hostname: Some("web01".to_string()),
            confidence: 85,
            evidence: Vec::new(),
            detection_methods: vec!["central_outbound_observation".to_string()],
            impact_level: ImpactLevel::High,
        }];

        let score = analyzer.calculate_decommission_confidence(
            &[],
            &[],
            &inbound,
            &std::collections::HashMap::new(),
        );
        assert!(score < 50);
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
