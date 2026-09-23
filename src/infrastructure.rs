use anyhow::Result;
use std::collections::{HashMap, HashSet};
use crate::models::{ServerDependencyChain, AnalysisResult, Dependency, InboundDependency};

pub struct InfrastructureMapper;

impl InfrastructureMapper {
    pub fn build_full_dependency_graph(
        servers: &HashMap<String, (AnalysisResult, Vec<InboundDependency>)>,
    ) -> HashMap<String, ServerDependencyChain> {
        let mut chains = HashMap::new();

        for (server_name, (analysis, inbound)) in servers {
            let outbound_deps = analysis.dependencies.clone();
            let inbound_deps = inbound.clone();

            let is_single_point_of_failure = Self::is_critical_service(server_name, &outbound_deps, &inbound_deps);
            let total_impact = Self::calculate_total_impact(&inbound_deps);

            chains.insert(
                server_name.clone(),
                ServerDependencyChain {
                    server_name: server_name.clone(),
                    outbound_deps,
                    inbound_deps,
                    total_impact,
                    is_single_point_of_failure,
                },
            );
        }

        chains
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
                    if !visited.contains(hostname) {
                        cluster.extend(Self::dfs_cluster(hostname, chains, visited));
                    }
                }
            }

            // Follow inbound dependencies
            for inbound in &chain.inbound_deps {
                let source = &inbound.source_hostname;
                if let Some(hostname) = source {
                    if !visited.contains(hostname) {
                        cluster.extend(Self::dfs_cluster(hostname, chains, visited));
                    }
                }
            }
        }

        cluster
    }

    pub fn find_single_points_of_failure(
        chains: &HashMap<String, ServerDependencyChain>,
    ) -> Vec<String> {
        chains
            .iter()
            .filter(|(_, chain)| chain.is_single_point_of_failure)
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn is_critical_service(
        _server: &str,
        _outbound: &[Dependency],
        inbound: &[InboundDependency],
    ) -> bool {
        // A service is critical if many others depend on it
        // and those dependents have few alternatives
        inbound.len() > 3 && inbound.iter().any(|dep| {
            matches!(dep.impact_level, crate::models::ImpactLevel::Critical)
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

    pub fn shutdown_impact_analysis(
        server: &str,
        chains: &HashMap<String, ServerDependencyChain>,
    ) -> ShutdownImpact {
        let mut affected_servers = Vec::new();
        let mut cascade_risk = false;

        if let Some(chain) = chains.get(server) {
            for inbound in &chain.inbound_deps {
                if let Some(dependent) = &inbound.source_hostname {
                    affected_servers.push((
                        dependent.clone(),
                        inbound.impact_level.clone(),
                    ));

                    // Check if the dependent has no alternatives
                    if let Some(dep_chain) = chains.get(dependent) {
                        if dep_chain.outbound_deps.iter().all(|d| {
                            d.remote_addr == chain.server_name || d.hostname.as_ref() == Some(&chain.server_name)
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShutdownImpact {
    pub server: String,
    pub affected_servers: Vec<(String, crate::models::ImpactLevel)>,
    pub cascade_risk: bool,
    pub safe_to_shutdown: bool,
}
