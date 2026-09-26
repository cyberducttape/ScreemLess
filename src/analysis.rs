use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::db::Database;
use crate::models::*;

type RemoteDependencyKey = (String, u16, String);
type RemoteObservation = (DateTime<Utc>, HashSet<String>);

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

        let snapshots = self
            .db
            .get_snapshots_since(hostname, since.timestamp_millis())?;

        if snapshots.is_empty() {
            return Ok(AnalysisResult {
                observation_window_hours: hours,
                total_snapshots: 0,
                observation_span: (now, now),
                host_identity: HostIdentity::default(),
                coverage: Self::build_observation_coverage(&[], now, hours),
                dependencies: Vec::new(),
                inbound_dependencies: Vec::new(),
                observed_processes: HashMap::new(),
                risks: Vec::new(),
                decommission_confidence: 0,
                probe_statuses: ProbeStatuses::default(),
                inventory: SiteInventory::default(),
            });
        }

        let mut probe_statuses = ProbeStatuses::default();
        for snapshot in &snapshots {
            probe_statuses.merge(&snapshot.probe_statuses);
        }

        let first_snap = snapshots.first().unwrap();
        let last_snap = snapshots.last().unwrap();
        let coverage = Self::build_observation_coverage(&snapshots, now, hours);
        let host_identity = Self::merge_host_identity(&snapshots, hostname);

        let dependencies = self.infer_dependencies(&snapshots)?;
        let observed_processes = self.analyze_process_activity(&snapshots)?;

        let inbound_dependencies =
            self.infer_inbound_dependencies(hostname, since.timestamp_millis())?;

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
            &coverage,
        );
        if !probe_statuses.all_complete() {
            risks.push(RiskAssessment {
                name: "Incomplete observation data".to_string(),
                severity: RiskSeverity::Fail,
                description: "One or more collection probes failed or had incomplete attribution"
                    .to_string(),
                evidence: Self::probe_status_summary(&probe_statuses),
            });
            decommission_confidence = decommission_confidence.min(49);
        }

        let inventory = Self::build_inventory(&snapshots, &dependencies);
        Ok(AnalysisResult {
            observation_window_hours: hours,
            total_snapshots: snapshots.len(),
            observation_span: (first_snap.timestamp, last_snap.timestamp),
            host_identity,
            coverage,
            dependencies,
            inbound_dependencies,
            observed_processes,
            risks,
            decommission_confidence,
            probe_statuses,
            inventory,
        })
    }

    fn build_inventory(
        snapshots: &[ObservationSnapshot],
        dependencies: &[Dependency],
    ) -> SiteInventory {
        use std::collections::BTreeSet;
        let is_web_process = |name: &str| {
            let normalized = name.to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "nginx"
                    | "apache2"
                    | "httpd"
                    | "caddy"
                    | "lighttpd"
                    | "haproxy"
                    | "traefik"
                    | "envoy"
                    | "node"
                    | "nodejs"
                    | "gunicorn"
                    | "uwsgi"
            ) || normalized.starts_with("php-fpm")
        };

        let site_refs = snapshots
            .iter()
            .flat_map(|snapshot| snapshot.config_references.iter())
            .filter(|reference| {
                reference.context.starts_with("nginx site")
                    || reference.context.starts_with("apache site")
                    || reference.context.starts_with("caddy site")
            })
            .collect::<Vec<_>>();
        let configured_sites = !site_refs.is_empty();
        let mut websites = std::collections::BTreeMap::<String, WebsiteInventory>::new();

        for reference in &site_refs {
            let context_parts = reference.context.split("; ").collect::<Vec<_>>();
            let content_paths = context_parts
                .iter()
                .find_map(|part| part.strip_prefix("root="))
                .map(|path| vec![path.to_string()])
                .unwrap_or_default();
            let entry = websites
                .entry(reference.hostname.clone())
                .or_insert_with(|| WebsiteInventory {
                    name: reference.hostname.clone(),
                    status: "inactive".to_string(),
                    ports: Vec::new(),
                    availability_observations: 0,
                    listener_activity_observations: 0,
                    content_paths: Vec::new(),
                    tech_stack: Vec::new(),
                });
            if let Some(ports) = context_parts
                .iter()
                .find_map(|part| part.strip_prefix("ports="))
            {
                for port in ports.split(',').filter_map(|port| port.parse::<u16>().ok()) {
                    if !entry.ports.contains(&port) {
                        entry.ports.push(port);
                    }
                }
            }
            for path in content_paths {
                if !entry.content_paths.contains(&path) {
                    entry.content_paths.push(path);
                }
            }
        }

        let mut site_port_owners = HashMap::<u16, usize>::new();
        for site in websites.values() {
            for port in &site.ports {
                *site_port_owners.entry(*port).or_default() += 1;
            }
        }

        let web_services = |snapshot: &ObservationSnapshot| {
            snapshot
                .listening_services
                .iter()
                .filter(|service| {
                    is_web_process(&service.process_name) || matches!(service.port, 80 | 443)
                })
                .map(|service| (service.port, service.process_name.clone()))
                .collect::<Vec<_>>()
        };
        let latest_web_services = snapshots.last().map(web_services).unwrap_or_default();
        let latest_has_web = !latest_web_services.is_empty();

        for snapshot in snapshots {
            let services = web_services(snapshot);
            let inbound_connections = snapshot
                .network_connections
                .iter()
                .filter(|connection| {
                    matches!(connection.state.as_str(), "ESTABLISHED" | "CLOSE-WAIT")
                })
                .collect::<Vec<_>>();
            if configured_sites {
                for site in websites.values_mut() {
                    let matching_services = services
                        .iter()
                        .filter(|service| site.ports.is_empty() || site.ports.contains(&service.0))
                        .collect::<Vec<_>>();
                    if !matching_services.is_empty() {
                        site.availability_observations += 1;
                    }
                    // A socket port cannot identify which virtual host received
                    // the request. Do not duplicate traffic across sites sharing
                    // that port; only attribute it when the port is unambiguous.
                    site.listener_activity_observations += inbound_connections
                        .iter()
                        .filter(|connection| {
                            site_port_owners.get(&connection.local_port) == Some(&1)
                                && site.ports.contains(&connection.local_port)
                        })
                        .count();
                    for service in matching_services {
                        if !site.ports.contains(&service.0) {
                            site.ports.push(service.0);
                        }
                        if !site.tech_stack.contains(&service.1) {
                            site.tech_stack.push(service.1.clone());
                        }
                    }
                }
            } else {
                for service in services {
                    let key = format!("{}:{}", service.1, service.0);
                    let entry = websites
                        .entry(key.clone())
                        .or_insert_with(|| WebsiteInventory {
                            name: key,
                            status: "inactive".to_string(),
                            ports: Vec::new(),
                            availability_observations: 0,
                            listener_activity_observations: 0,
                            content_paths: Vec::new(),
                            tech_stack: Vec::new(),
                        });
                    entry.availability_observations += 1;
                    entry.listener_activity_observations += inbound_connections
                        .iter()
                        .filter(|connection| connection.local_port == service.0)
                        .count();
                    if !entry.ports.contains(&service.0) {
                        entry.ports.push(service.0);
                    }
                    if !entry.tech_stack.contains(&service.1) {
                        entry.tech_stack.push(service.1.clone());
                    }
                }
            }
        }
        for site in websites.values_mut() {
            site.status = if latest_has_web
                && latest_web_services
                    .iter()
                    .any(|service| site.ports.is_empty() || site.ports.contains(&service.0))
            {
                "active"
            } else {
                "inactive"
            }
            .to_string();
        }

        let mut users = BTreeSet::new();
        let mut stack = BTreeSet::new();
        let mut software = std::collections::BTreeMap::<
            (String, Option<String>, Option<String>),
            SoftwareInventory,
        >::new();
        for snapshot in snapshots {
            for process in &snapshot.processes {
                users.insert(process.user.clone());
            }
            for observed in &snapshot.software {
                let key = (
                    observed.name.clone(),
                    observed.version.clone(),
                    observed.executable.clone(),
                );
                if let Some(entry) = software.get_mut(&key) {
                    entry.observations += observed.observations;
                } else {
                    software.insert(key, observed.clone());
                }
                stack.insert(observed.name.clone());
            }
            for service in &snapshot.listening_services {
                users.insert(service.user.clone());
                if is_web_process(&service.process_name) {
                    stack.insert(service.process_name.clone());
                }
            }
        }
        let classify = |dependency: &Dependency| {
            let contexts = dependency
                .config_references
                .iter()
                .map(|reference| reference.context.to_ascii_lowercase())
                .collect::<Vec<_>>();
            let storage = matches!(dependency.remote_port, 2049 | 445 | 139 | 111)
                || dependency.protocol.eq_ignore_ascii_case("nfs")
                || contexts.iter().any(|context| {
                    context.contains("storage")
                        || context.contains("nfs")
                        || context.contains("s3")
                        || context.contains("object")
                });
            let database = matches!(
                dependency.remote_port,
                3306 | 5432 | 1433 | 1521 | 27017 | 6379 | 5984 | 9200
            ) || contexts.iter().any(|context| {
                context.contains("database")
                    || context.contains("redis")
                    || context.contains("elasticsearch")
                    || context.contains("cache")
            });
            (database, storage)
        };
        let mut databases = Vec::new();
        let mut storage_connections = Vec::new();
        for dependency in dependencies {
            let (database, storage) = classify(dependency);
            let target = dependency
                .hostname
                .clone()
                .unwrap_or_else(|| dependency.remote_addr.clone());
            let item = InventoryConnection {
                target,
                port: dependency.remote_port,
                protocol: dependency.protocol.clone(),
                usage_observations: dependency.connection_count,
                evidence: "Observed outbound connection".to_string(),
            };
            if database {
                databases.push(item.clone());
            }
            if storage {
                storage_connections.push(item);
            }
        }
        let mut load_balancers = BTreeSet::new();
        for reference in snapshots
            .iter()
            .flat_map(|snapshot| snapshot.config_references.iter())
        {
            let candidate = if reference.context.starts_with("haproxy") {
                Some("haproxy")
            } else if reference.context.starts_with("traefik") {
                Some("traefik")
            } else if reference.context == "caddy reverse_proxy" {
                Some("caddy")
            } else if reference.context == "proxy_pass" || reference.context == "nginx upstream" {
                Some("nginx")
            } else if reference.context == "apache proxy_pass" {
                Some("apache")
            } else {
                None
            };
            if let Some(candidate) = candidate {
                load_balancers.insert(candidate.to_string());
            }
        }
        SiteInventory {
            websites: websites.into_values().collect(),
            users: users.into_iter().collect(),
            databases,
            storage_connections,
            tech_stack: stack.into_iter().collect(),
            software: software.into_values().collect(),
            load_balancers: load_balancers.into_iter().collect(),
        }
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
        let mut target_ips = snapshots
            .iter()
            .filter(|snapshot| Self::identity_matches(&snapshot.host_identity, target_hostname))
            .flat_map(|snapshot| Self::identity_addresses(&snapshot.host_identity))
            .collect::<HashSet<_>>();
        target_ips.extend(
            snapshots
                .iter()
                .flat_map(|snapshot| snapshot.dns_names.iter())
                .filter(|dns| dns.hostname.eq_ignore_ascii_case(target_hostname))
                .flat_map(|dns| dns.ip_addresses.iter().cloned()),
        );
        if target.parse::<IpAddr>().is_ok() {
            target_ips.insert(target.clone());
        }
        let mut sources: HashMap<String, SourceEvidence> = HashMap::new();

        for snapshot in snapshots {
            let source = snapshot.hostname.clone();
            if source.eq_ignore_ascii_case(target_hostname) {
                continue;
            }

            for connection in snapshot.network_connections.iter().filter(|connection| {
                connection.remote_addr.eq_ignore_ascii_case(&target)
                    || target_ips.contains(&connection.remote_addr)
            }) {
                let evidence = sources
                    .entry(source.clone())
                    .or_insert_with(|| SourceEvidence {
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
            let confidence = if evidence.complete {
                confidence
            } else {
                confidence.min(69)
            };
            let port_list = evidence
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let process_list = evidence
                .processes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");

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

        inbound.sort_by_key(|item| std::cmp::Reverse(item.confidence));
        Ok(inbound)
    }

    fn infer_dependencies(&self, snapshots: &[ObservationSnapshot]) -> Result<Vec<Dependency>> {
        let mut remote_hosts: HashMap<RemoteDependencyKey, Vec<RemoteObservation>> = HashMap::new();

        for snapshot in snapshots {
            for conn in &snapshot.network_connections {
                let key = (
                    conn.remote_addr.clone(),
                    conn.remote_port,
                    conn.protocol.clone(),
                );
                let mut processes = HashSet::new();
                processes.insert(conn.process_name.clone());

                remote_hosts
                    .entry(key)
                    .or_default()
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
                        || hostname
                            .as_ref()
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

        dependencies.sort_by_key(|dependency| std::cmp::Reverse(dependency.connection_count));
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
                    .or_default()
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
                description: "Server is listening on ports (likely has inbound dependencies)"
                    .to_string(),
                evidence: "Listening services detected in observations".to_string(),
            });
        }

        for inbound in inbound_dependencies {
            let source = inbound
                .source_hostname
                .as_deref()
                .unwrap_or(&inbound.source_ip);
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
                evidence: inbound
                    .evidence
                    .iter()
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
                    description: format!(
                        "Connection to {}:{} observed only once",
                        dep.remote_addr, dep.remote_port
                    ),
                    evidence: "Single observation of this connection in window".to_string(),
                });
            }
        }

        for proc in observed_processes.values() {
            if proc.observed_once_in_window
                && (proc.name.contains("backup")
                    || proc.name.contains("sync")
                    || proc.name.contains("update"))
            {
                risks.push(RiskAssessment {
                    name: "Critical process seen once".to_string(),
                    severity: RiskSeverity::Warn,
                    description: format!(
                        "Process '{}' appeared only once in observation window",
                        proc.name
                    ),
                    evidence: format!(
                        "Last seen {}",
                        proc.last_seen.format("%Y-%m-%d %H:%M:%S UTC")
                    ),
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

        // Confidence is intentionally monotonic: adding corroborating evidence
        // cannot lower the result. Strength is represented by the strongest
        // signal, while diversity and repeated observations add support.
        let strongest = evidence
            .iter()
            .map(|item| u16::from(item.level.score()))
            .max()
            .unwrap_or(0);
        let diversity = evidence
            .iter()
            .map(|item| item.level.clone())
            .collect::<HashSet<_>>()
            .len() as u16;
        let frequency = (evidence.len().min(5) as u16) * 4;
        (strongest * 20 + diversity * 10 + frequency).min(100) as u8
    }

    fn build_ip_to_hostname_map(
        &self,
        snapshots: &[ObservationSnapshot],
    ) -> HashMap<String, String> {
        let mut map = HashMap::new();

        for snapshot in snapshots {
            for ip in Self::identity_addresses(&snapshot.host_identity) {
                map.insert(ip, snapshot.host_identity.hostname.clone());
            }
            for dns in &snapshot.dns_names {
                for ip in &dns.ip_addresses {
                    map.insert(ip.clone(), dns.hostname.clone());
                }
            }
        }

        map
    }

    fn identity_matches(identity: &HostIdentity, target: &str) -> bool {
        [
            identity.hostname.as_str(),
            identity.fqdn.as_deref().unwrap_or_default(),
            identity.short_hostname.as_str(),
        ]
        .into_iter()
        .any(|name| name.eq_ignore_ascii_case(target))
            || identity
                .dns_aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(target))
    }

    fn identity_addresses(identity: &HostIdentity) -> HashSet<String> {
        identity
            .ipv4_addresses
            .iter()
            .chain(identity.ipv6_addresses.iter())
            .chain(identity.vip_addresses.iter())
            .chain(identity.interface_addresses.iter())
            .chain(identity.container_addresses.iter())
            .cloned()
            .collect()
    }

    fn merge_host_identity(
        snapshots: &[ObservationSnapshot],
        target_hostname: &str,
    ) -> HostIdentity {
        let relevant = snapshots
            .iter()
            .filter(|snapshot| Self::identity_matches(&snapshot.host_identity, target_hostname))
            .map(|snapshot| &snapshot.host_identity)
            .collect::<Vec<_>>();
        let source = relevant
            .last()
            .copied()
            .or_else(|| snapshots.last().map(|snapshot| &snapshot.host_identity));
        let Some(source) = source else {
            return HostIdentity::default();
        };
        let mut merged = source.clone();
        let add_unique = |values: &mut Vec<String>, additions: Vec<String>| {
            for value in additions {
                if !values.contains(&value) {
                    values.push(value);
                }
            }
        };
        for identity in relevant {
            add_unique(&mut merged.ipv4_addresses, identity.ipv4_addresses.clone());
            add_unique(&mut merged.ipv6_addresses, identity.ipv6_addresses.clone());
            add_unique(&mut merged.vip_addresses, identity.vip_addresses.clone());
            add_unique(
                &mut merged.interface_addresses,
                identity.interface_addresses.clone(),
            );
            add_unique(&mut merged.dns_aliases, identity.dns_aliases.clone());
            add_unique(
                &mut merged.container_addresses,
                identity.container_addresses.clone(),
            );
        }
        merged
    }

    fn calculate_decommission_confidence(
        &self,
        snapshots: &[ObservationSnapshot],
        dependencies: &[Dependency],
        inbound_dependencies: &[InboundDependency],
        observed_processes: &HashMap<String, ProcessActivity>,
        coverage: &ObservationCoverage,
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
                p.observed_once_in_window && (p.name.contains("backup") || p.name.contains("sync"))
            })
            .count();

        if one_time_critical > 0 {
            score = score.saturating_sub((one_time_critical as u16) * 10);
        }

        let has_cron = !snapshots.iter().all(|s| s.cron_jobs.is_empty());
        if has_cron {
            score = score.saturating_sub(20);
        }

        let coverage_cap = coverage.coverage_percent.round().clamp(0.0, 100.0) as u16;
        let quality_cap = if coverage.evidence_quality == "HIGH" {
            100
        } else if coverage.evidence_quality == "MEDIUM" {
            79
        } else {
            49
        };
        score.min(coverage_cap).min(quality_cap) as u8
    }

    fn build_observation_coverage(
        snapshots: &[ObservationSnapshot],
        now: DateTime<Utc>,
        requested_window_hours: u32,
    ) -> ObservationCoverage {
        let actual_span_seconds = snapshots
            .first()
            .zip(snapshots.last())
            .map(|(first, last)| (last.timestamp - first.timestamp).num_seconds().max(0))
            .unwrap_or(0);
        let interval_seconds = Self::estimated_interval_seconds(snapshots);
        let requested_seconds = i64::from(requested_window_hours.max(1)) * 3600;
        let expected_samples =
            ((requested_seconds as f64 / interval_seconds as f64).ceil() as usize).max(1);
        let successful_samples = snapshots.len();
        let coverage_percent =
            ((successful_samples as f64 / expected_samples as f64) * 100.0).min(100.0);

        let probe_names = [
            "network_sockets",
            "process_attribution",
            "dns",
            "config_scan",
            "cron",
            "systemd",
        ];
        let mut probe_coverage = HashMap::new();
        let mut remaining_unknowns = Vec::new();
        for name in probe_names {
            let complete = snapshots
                .iter()
                .filter(|snapshot| Self::probe_status(snapshot, name).is_complete())
                .count();
            let percent = if snapshots.is_empty() {
                0.0
            } else {
                complete as f64 * 100.0 / snapshots.len() as f64
            };
            probe_coverage.insert(name.to_string(), percent);
            if percent < 100.0 {
                let detail = snapshots
                    .iter()
                    .filter_map(|snapshot| Self::probe_status(snapshot, name).details.as_deref())
                    .next()
                    .unwrap_or("probe was incomplete");
                remaining_unknowns.push(format!("{}: {}", name, detail));
            }
        }
        if coverage_percent < 90.0 {
            remaining_unknowns.push("observation window is not sufficiently covered".to_string());
        }
        if let Some(last) = snapshots.last() {
            let freshness = (now - last.timestamp).num_seconds().max(0);
            if freshness > interval_seconds * 2 {
                remaining_unknowns.push(format!("last observation is {} seconds old", freshness));
            }
        } else {
            remaining_unknowns.push("no successful observations".to_string());
        }

        let privileges = if !snapshots.is_empty()
            && snapshots
                .iter()
                .all(|snapshot| snapshot.privileges == "full")
        {
            "full".to_string()
        } else if snapshots
            .iter()
            .any(|snapshot| snapshot.privileges == "restricted")
        {
            "restricted".to_string()
        } else {
            "unknown".to_string()
        };
        if privileges != "full" {
            remaining_unknowns.push("collector is not running with full privileges".to_string());
        }
        let evidence_quality = if coverage_percent >= 90.0
            && probe_coverage.values().all(|percent| *percent >= 99.0)
            && privileges == "full"
        {
            "HIGH"
        } else if coverage_percent >= 50.0 && !snapshots.is_empty() {
            "MEDIUM"
        } else {
            "LOW"
        };

        ObservationCoverage {
            requested_window_hours,
            actual_span_seconds,
            expected_samples,
            successful_samples,
            coverage_percent,
            last_observation: snapshots.last().map(|snapshot| snapshot.timestamp),
            probe_coverage,
            privileges,
            evidence_quality: evidence_quality.to_string(),
            remaining_unknowns,
        }
    }

    fn probe_status<'snapshot>(
        snapshot: &'snapshot ObservationSnapshot,
        name: &str,
    ) -> &'snapshot ProbeStatus {
        match name {
            "network_sockets" => &snapshot.probe_statuses.network_sockets,
            "process_attribution" => &snapshot.probe_statuses.process_attribution,
            "dns" => &snapshot.probe_statuses.dns,
            "config_scan" => &snapshot.probe_statuses.config_scan,
            "cron" => &snapshot.probe_statuses.cron,
            "systemd" => &snapshot.probe_statuses.systemd,
            _ => unreachable!("unknown probe name"),
        }
    }

    fn estimated_interval_seconds(snapshots: &[ObservationSnapshot]) -> i64 {
        let mut intervals = snapshots
            .iter()
            .filter_map(|snapshot| snapshot.sampling_interval_seconds)
            .map(|seconds| seconds.max(1) as i64)
            .collect::<Vec<_>>();
        if intervals.is_empty() {
            intervals = snapshots
                .windows(2)
                .map(|pair| (pair[1].timestamp - pair[0].timestamp).num_seconds().max(1))
                .collect();
        }
        intervals.sort_unstable();
        intervals.get(intervals.len() / 2).copied().unwrap_or(60)
    }
}

#[cfg(test)]
mod tests {
    use super::Analyzer;
    use crate::db::Database;
    use crate::models::{
        ConfigReference, Evidence, EvidenceLevel, HostIdentity, ImpactLevel, InboundDependency,
        ListeningService, NetworkConnection, ObservationCoverage, ObservationSnapshot,
        ProbeStatuses, Process, SoftwareInventory,
    };
    use chrono::Utc;

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
            &ObservationCoverage {
                coverage_percent: 100.0,
                evidence_quality: "HIGH".to_string(),
                ..ObservationCoverage::default()
            },
        );
        assert!(score < 50);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn confidence_does_not_drop_when_corroborating_evidence_is_added() {
        let high = vec![
            Evidence {
                level: EvidenceLevel::High,
                description: "first".to_string(),
            },
            Evidence {
                level: EvidenceLevel::High,
                description: "second".to_string(),
            },
        ];
        let mut corroborated = high.clone();
        corroborated.push(Evidence {
            level: EvidenceLevel::Med,
            description: "independent corroboration".to_string(),
        });

        assert!(
            Analyzer::calculate_confidence(&corroborated) >= Analyzer::calculate_confidence(&high)
        );
    }

    #[test]
    fn one_snapshot_cannot_claim_full_observation_coverage() {
        let now = Utc::now();
        let snapshot = ObservationSnapshot {
            timestamp: now,
            hostname: "web01".to_string(),
            host_identity: HostIdentity {
                hostname: "web01".to_string(),
                ..HostIdentity::default()
            },
            listening_services: Vec::new(),
            network_connections: Vec::new(),
            processes: Vec::new(),
            cron_jobs: Vec::new(),
            systemd_timers: Vec::new(),
            dns_names: Vec::new(),
            config_references: Vec::new(),
            software: Vec::new(),
            sampling_interval_seconds: Some(60),
            privileges: "full".to_string(),
            probe_statuses: ProbeStatuses::default(),
        };

        let coverage = Analyzer::build_observation_coverage(&[snapshot], now, 168);
        assert_eq!(coverage.expected_samples, 10_080);
        assert_eq!(coverage.successful_samples, 1);
        assert!(coverage.coverage_percent < 1.0);
        assert_eq!(coverage.evidence_quality, "LOW");
    }

    #[test]
    fn inbound_dependencies_use_target_host_identity_addresses() {
        let path = std::env::temp_dir().join(format!(
            "screamless-inbound-identity-test-{}.db",
            std::process::id()
        ));
        let mut db = Database::new(&path).unwrap();
        let now = Utc::now();
        let source = ObservationSnapshot {
            timestamp: now,
            hostname: "web01".to_string(),
            host_identity: HostIdentity {
                hostname: "web01".to_string(),
                ..HostIdentity::default()
            },
            listening_services: Vec::new(),
            network_connections: vec![NetworkConnection {
                local_addr: "10.20.30.10".to_string(),
                local_port: 51000,
                remote_addr: "10.20.30.40".to_string(),
                remote_port: 5432,
                protocol: "tcp".to_string(),
                state: "ESTABLISHED".to_string(),
                pid: 1,
                process_name: "app".to_string(),
            }],
            processes: Vec::new(),
            cron_jobs: Vec::new(),
            systemd_timers: Vec::new(),
            dns_names: Vec::new(),
            config_references: Vec::new(),
            software: Vec::new(),
            sampling_interval_seconds: Some(60),
            privileges: "full".to_string(),
            probe_statuses: ProbeStatuses::default(),
        };
        let target = ObservationSnapshot {
            timestamp: now + chrono::Duration::seconds(1),
            hostname: "db01".to_string(),
            host_identity: HostIdentity {
                hostname: "db01".to_string(),
                ipv4_addresses: vec!["10.20.30.40".to_string()],
                ..HostIdentity::default()
            },
            listening_services: Vec::new(),
            network_connections: Vec::new(),
            processes: Vec::new(),
            cron_jobs: Vec::new(),
            systemd_timers: Vec::new(),
            dns_names: Vec::new(),
            config_references: Vec::new(),
            software: Vec::new(),
            sampling_interval_seconds: Some(60),
            privileges: "full".to_string(),
            probe_statuses: ProbeStatuses::default(),
        };
        db.store_snapshot(&source).unwrap();
        db.store_snapshot(&target).unwrap();

        let inbound = Analyzer::new(&db)
            .infer_inbound_dependencies("db01", 0)
            .unwrap();
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].source_hostname.as_deref(), Some("web01"));
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn inventory_uses_virtual_host_identity_and_inbound_socket_evidence() {
        let snapshot = ObservationSnapshot {
            timestamp: Utc::now(),
            hostname: "web01".to_string(),
            host_identity: HostIdentity {
                hostname: "web01".to_string(),
                ..HostIdentity::default()
            },
            listening_services: vec![ListeningService {
                port: 443,
                protocol: "tcp".to_string(),
                process_name: "nginx".to_string(),
                pid: 10,
                user: "www-data".to_string(),
            }],
            network_connections: vec![NetworkConnection {
                local_addr: "10.0.0.1".to_string(),
                local_port: 443,
                remote_addr: "10.0.0.9".to_string(),
                remote_port: 53122,
                protocol: "tcp".to_string(),
                state: "ESTABLISHED".to_string(),
                pid: 10,
                process_name: "nginx".to_string(),
            }],
            processes: vec![Process {
                pid: 10,
                name: "nginx".to_string(),
                user: "www-data".to_string(),
                cmdline: String::new(),
            }],
            cron_jobs: Vec::new(),
            systemd_timers: Vec::new(),
            dns_names: Vec::new(),
            config_references: vec![ConfigReference {
                file_path: "/etc/nginx/sites-enabled/example".to_string(),
                hostname: "example.com".to_string(),
                port: None,
                context: "nginx site; root=/srv/example/public; ports=443".to_string(),
                config_line: None,
            }],
            software: Vec::new(),
            sampling_interval_seconds: None,
            privileges: "full".to_string(),
            probe_statuses: ProbeStatuses::default(),
        };

        let inventory = Analyzer::build_inventory(std::slice::from_ref(&snapshot), &[]);
        assert_eq!(inventory.websites.len(), 1);
        assert_eq!(inventory.websites[0].name, "example.com");
        assert_eq!(inventory.websites[0].status, "active");
        assert_eq!(
            inventory.websites[0].content_paths,
            vec!["/srv/example/public"]
        );
        assert_eq!(inventory.websites[0].listener_activity_observations, 1);
        assert!(inventory.users.contains(&"www-data".to_string()));

        let mut shared_port_snapshot = snapshot.clone();
        shared_port_snapshot
            .config_references
            .push(ConfigReference {
                file_path: "/etc/nginx/sites-enabled/second".to_string(),
                hostname: "second.example.com".to_string(),
                port: None,
                context: "nginx site; root=/srv/second/public; ports=443".to_string(),
                config_line: None,
            });
        let shared_port_inventory = Analyzer::build_inventory(&[shared_port_snapshot], &[]);
        assert_eq!(shared_port_inventory.websites.len(), 2);
        assert!(shared_port_inventory
            .websites
            .iter()
            .all(|site| site.listener_activity_observations == 0));

        let mut proxy_snapshot = snapshot;
        proxy_snapshot.config_references.push(ConfigReference {
            file_path: "/etc/nginx/sites-enabled/proxy".to_string(),
            hostname: "app.internal".to_string(),
            port: Some(8080),
            context: "proxy_pass".to_string(),
            config_line: None,
        });
        proxy_snapshot.software = ["python", "php", "node", "postgres"]
            .into_iter()
            .map(|name| SoftwareInventory {
                name: name.to_string(),
                version: None,
                executable: None,
                evidence: "test".to_string(),
                observations: 1,
            })
            .collect();
        let proxy_inventory = Analyzer::build_inventory(&[proxy_snapshot], &[]);
        assert_eq!(proxy_inventory.load_balancers, vec!["nginx"]);
        assert!(proxy_inventory.tech_stack.contains(&"python".to_string()));
        assert!(!proxy_inventory
            .load_balancers
            .contains(&"python".to_string()));
    }
}
