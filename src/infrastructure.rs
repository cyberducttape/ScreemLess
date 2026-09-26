use crate::models::{
    AnalysisResult, Dependency, Evidence, EvidenceLevel, ImpactLevel, InboundDependency,
    ServerDependencyChain,
};
use std::collections::{HashMap, HashSet};

pub struct InfrastructureMapper;

impl InfrastructureMapper {
    pub fn build_full_dependency_graph(
        servers: &HashMap<String, (AnalysisResult, Vec<InboundDependency>)>,
    ) -> HashMap<String, ServerDependencyChain> {
        let mut chains = HashMap::new();
        let inferred_inbound = Self::reverse_observed_edges(servers);

        for (server_name, (analysis, _)) in servers {
            let outbound_deps = analysis.dependencies.clone();
            let inbound_deps = inferred_inbound
                .get(server_name)
                .cloned()
                .unwrap_or_default();

            let is_high_fan_in =
                Self::is_critical_service(server_name, &outbound_deps, &inbound_deps);
            let total_impact = Self::calculate_total_impact(&inbound_deps);

            chains.insert(
                server_name.clone(),
                ServerDependencyChain {
                    server_name: server_name.clone(),
                    outbound_deps,
                    inbound_deps,
                    total_impact,
                    is_high_fan_in,
                },
            );
        }

        chains
    }

    fn reverse_observed_edges(
        servers: &HashMap<String, (AnalysisResult, Vec<InboundDependency>)>,
    ) -> HashMap<String, Vec<InboundDependency>> {
        let mut inbound = HashMap::<String, Vec<InboundDependency>>::new();

        for (source, (analysis, _)) in servers {
            for dependency in &analysis.dependencies {
                let target = dependency
                    .hostname
                    .as_deref()
                    .filter(|hostname| servers.contains_key(*hostname))
                    .or_else(|| {
                        servers
                            .contains_key(&dependency.remote_addr)
                            .then_some(dependency.remote_addr.as_str())
                    });
                let Some(target) = target else { continue };
                if target == source {
                    continue;
                }

                let entry = inbound.entry(target.to_string()).or_default();
                if let Some(existing) = entry
                    .iter_mut()
                    .find(|edge| edge.source_hostname.as_deref() == Some(source.as_str()))
                {
                    existing.confidence = existing.confidence.max(dependency.confidence);
                    existing.evidence.push(Evidence {
                        level: EvidenceLevel::Med,
                        description: format!(
                            "Additional observed outbound connection on port {}",
                            dependency.remote_port
                        ),
                    });
                } else {
                    entry.push(InboundDependency {
                        source_ip: "unknown".to_string(),
                        source_hostname: Some(source.clone()),
                        confidence: dependency.confidence,
                        evidence: vec![Evidence {
                            level: if dependency.confidence >= 70 {
                                EvidenceLevel::High
                            } else {
                                EvidenceLevel::Med
                            },
                            description: format!(
                                "Observed outbound {} connection to port {} ({} observation(s))",
                                dependency.protocol,
                                dependency.remote_port,
                                dependency.connection_count
                            ),
                        }],
                        detection_methods: vec!["central_outbound_observation".to_string()],
                        impact_level: if dependency.confidence >= 85 {
                            ImpactLevel::High
                        } else {
                            ImpactLevel::Medium
                        },
                    });
                }
            }
        }

        inbound
    }

    pub fn find_dependency_clusters(
        chains: &HashMap<String, ServerDependencyChain>,
    ) -> Vec<Vec<String>> {
        let mut clusters = Vec::new();
        let mut visited = HashSet::new();

        for server in chains.keys() {
            if visited.contains(server) {
                continue;
            }

            let cluster = Self::dfs_cluster(server, chains, &mut visited);
            if cluster.len() > 1 {
                clusters.push(cluster);
            }
        }

        clusters
    }

    fn dfs_cluster(
        server: &str,
        chains: &HashMap<String, ServerDependencyChain>,
        visited: &mut HashSet<String>,
    ) -> Vec<String> {
        let mut cluster = vec![server.to_string()];
        visited.insert(server.to_string());

        if let Some(chain) = chains.get(server) {
            // Follow outbound dependencies
            for dep in &chain.outbound_deps {
                if let Some(hostname) = &dep.hostname {
                    if chains.contains_key(hostname) && !visited.contains(hostname) {
                        cluster.extend(Self::dfs_cluster(hostname, chains, visited));
                    }
                }
            }

            // Follow inbound dependencies
            for inbound in &chain.inbound_deps {
                let source = &inbound.source_hostname;
                if let Some(hostname) = source {
                    if chains.contains_key(hostname) && !visited.contains(hostname) {
                        cluster.extend(Self::dfs_cluster(hostname, chains, visited));
                    }
                }
            }
        }

        cluster
    }

    pub fn find_high_fan_in_services(
        chains: &HashMap<String, ServerDependencyChain>,
    ) -> Vec<String> {
        chains
            .iter()
            .filter(|(_, chain)| chain.is_high_fan_in)
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn is_critical_service(
        _server: &str,
        _outbound: &[Dependency],
        inbound: &[InboundDependency],
    ) -> bool {
        // This is only a high-fan-in heuristic. Redundancy and alternate paths
        // are not collected, so it is not proof of a single point of failure.
        inbound.len() > 3
            && inbound.iter().any(|dep| {
                dep.confidence >= 70
                    || matches!(
                        dep.impact_level,
                        crate::models::ImpactLevel::Critical | crate::models::ImpactLevel::High
                    )
            })
    }

    fn calculate_total_impact(inbound: &[InboundDependency]) -> u8 {
        let mut impact = 0u16;

        for dep in inbound {
            impact += match dep.impact_level {
                crate::models::ImpactLevel::Critical => 40,
                crate::models::ImpactLevel::High => 25,
                crate::models::ImpactLevel::Medium => 15,
                crate::models::ImpactLevel::Low => 5,
            };
        }

        (impact.min(100)) as u8
    }

    #[allow(dead_code)]
    pub fn shutdown_impact_analysis(
        server: &str,
        chains: &HashMap<String, ServerDependencyChain>,
    ) -> ShutdownImpact {
        let mut affected_servers = Vec::new();
        let mut cascade_risk = false;

        if let Some(chain) = chains.get(server) {
            for inbound in &chain.inbound_deps {
                if let Some(dependent) = &inbound.source_hostname {
                    affected_servers.push((dependent.clone(), inbound.impact_level.clone()));

                    // Check if the dependent has no alternatives
                    if let Some(dep_chain) = chains.get(dependent) {
                        if dep_chain.outbound_deps.iter().all(|d| {
                            d.remote_addr == chain.server_name
                                || d.hostname.as_ref() == Some(&chain.server_name)
                        }) {
                            cascade_risk = true;
                        }
                    }
                }
            }
        }

        affected_servers.sort_by(|a, b| {
            use crate::models::ImpactLevel;
            match (&b.1, &a.1) {
                (ImpactLevel::Critical, ImpactLevel::Critical) => a.0.cmp(&b.0),
                (ImpactLevel::Critical, _) => std::cmp::Ordering::Greater,
                (_, ImpactLevel::Critical) => std::cmp::Ordering::Less,
                (ImpactLevel::High, ImpactLevel::High) => a.0.cmp(&b.0),
                (ImpactLevel::High, _) => std::cmp::Ordering::Greater,
                _ => a.0.cmp(&b.0),
            }
        });

        ShutdownImpact {
            server: server.to_string(),
            affected_servers,
            cascade_risk,
            safe_to_shutdown: false,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShutdownImpact {
    pub server: String,
    pub affected_servers: Vec<(String, crate::models::ImpactLevel)>,
    pub cascade_risk: bool,
    pub safe_to_shutdown: bool,
}

#[cfg(test)]
mod tests {
    use super::InfrastructureMapper;
    use crate::models::{AnalysisResult, Dependency, ProbeStatuses};
    use chrono::Utc;

    fn analysis(dependencies: Vec<Dependency>) -> AnalysisResult {
        let now = Utc::now();
        AnalysisResult {
            observation_window_hours: 1,
            total_snapshots: 1,
            observation_span: (now, now),
            coverage: crate::models::ObservationCoverage::default(),
            dependencies,
            inbound_dependencies: Vec::new(),
            observed_processes: std::collections::HashMap::new(),
            risks: Vec::new(),
            decommission_confidence: 100,
            probe_statuses: ProbeStatuses::default(),
            inventory: crate::models::SiteInventory::default(),
        }
    }

    #[test]
    fn reverses_observed_outbound_edge_into_inbound_dependency() {
        let now = Utc::now();
        let dependency = Dependency {
            remote_addr: "10.0.0.2".to_string(),
            remote_port: 3306,
            protocol: "tcp".to_string(),
            connection_count: 4,
            first_seen: now,
            last_seen: now,
            processes: vec!["billing".to_string()],
            confidence: 85,
            evidence: Vec::new(),
            config_references: Vec::new(),
            hostname: Some("db01".to_string()),
        };

        let mut servers = std::collections::HashMap::new();
        servers.insert(
            "web01".to_string(),
            (analysis(vec![dependency]), Vec::new()),
        );
        servers.insert("db01".to_string(), (analysis(Vec::new()), Vec::new()));

        let graph = InfrastructureMapper::build_full_dependency_graph(&servers);
        let inbound = &graph["db01"].inbound_deps;
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].source_hostname.as_deref(), Some("web01"));
        assert_eq!(
            inbound[0].detection_methods,
            vec!["central_outbound_observation"]
        );
    }
}
