use anyhow::Result;
use std::fs;
use regex::Regex;
use std::collections::HashMap;

use crate::models::{InboundDependency, Evidence, EvidenceLevel, ImpactLevel};

pub struct ReverseInference;

impl ReverseInference {
    pub fn infer_inbound_dependencies(hostname: &str, local_ips: &[String]) -> Result<Vec<InboundDependency>> {
        let mut inbound = Vec::new();

        inbound.extend(Self::detect_from_access_logs(hostname)?);
        inbound.extend(Self::detect_from_etc_hosts(hostname, local_ips)?);
        inbound.extend(Self::detect_from_ssh_keys(hostname)?);
        inbound.extend(Self::detect_from_dns_records(hostname)?);
        inbound.extend(Self::detect_from_git_config(hostname)?);
        inbound.extend(Self::detect_from_nfs_mounts(hostname)?);

        // Deduplicate and merge evidence
        inbound.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        inbound.dedup_by(|a, b| {
            a.source_ip == b.source_ip
                || (a.source_hostname.is_some() && a.source_hostname == b.source_hostname)
        });

        Ok(inbound)
    }

    fn detect_from_access_logs(_hostname: &str) -> Result<Vec<InboundDependency>> {
        let mut deps = Vec::new();
        let log_paths = vec![
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access.log",
            "/var/log/syslog",
            "/var/log/auth.log",
        ];

        let ip_pattern = Regex::new(r"(\d+\.\d+\.\d+\.\d+)")?;
        let mut ip_counts: HashMap<String, usize> = HashMap::new();

        for log_path in log_paths {
            if let Ok(content) = fs::read_to_string(log_path) {
                let lines: Vec<&str> = content.lines().collect();
                let recent = lines.iter().rev().take(10000);

                for line in recent {
                    if let Some(caps) = ip_pattern.captures(line) {
                        if let Some(ip) = caps.get(1) {
                            let ip_str = ip.as_str();
                            if !ip_str.starts_with("127.") && !ip_str.starts_with("::1") {
                                *ip_counts.entry(ip_str.to_string()).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        }

        for (ip, count) in ip_counts {
            if count > 10 {
                let confidence = ((count.min(255) * 100) / 255).min(95) as u8;
                deps.push(InboundDependency {
                    source_ip: ip,
                    source_hostname: None,
                    confidence,
                    evidence: vec![Evidence {
                        level: EvidenceLevel::High,
                        description: format!("{} requests in recent logs", count),
                    }],
                    detection_methods: vec!["access_logs".to_string()],
                    impact_level: ImpactLevel::High,
                });
            }
        }

        Ok(deps)
    }

    fn detect_from_etc_hosts(hostname: &str, _local_ips: &[String]) -> Result<Vec<InboundDependency>> {
        let mut deps = Vec::new();

        if let Ok(content) = fs::read_to_string("/etc/hosts") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    for part in &parts[1..] {
                        if *part == hostname || part.ends_with(&format!(".{}", hostname)) {
                            let ip = parts[0];
                            deps.push(InboundDependency {
                                source_ip: ip.to_string(),
                                source_hostname: None,
                                confidence: 75,
                                evidence: vec![Evidence {
                                    level: EvidenceLevel::Med,
                                    description: format!("Entry in /etc/hosts: {} -> {}", ip, hostname),
                                }],
                                detection_methods: vec!["etc_hosts".to_string()],
                                impact_level: ImpactLevel::Medium,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(deps)
    }

    fn detect_from_ssh_keys(hostname: &str) -> Result<Vec<InboundDependency>> {
        let mut deps = Vec::new();

        let key_paths = vec![
            "/root/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys",
            "/root/.ssh/config",
            "/home/*/.ssh/config",
        ];

        let host_re = Regex::new(&format!(
            r"(?i)(?:host|hostname|from=.*?).*?{}",
            regex::escape(hostname)
        ))?;

        for pattern in key_paths {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(&entry) {
                        if host_re.is_match(&content) {
                            deps.push(InboundDependency {
                                source_ip: "unknown".to_string(),
                                source_hostname: None,
                                confidence: 65,
                                evidence: vec![Evidence {
                                    level: EvidenceLevel::Med,
                                    description: format!(
                                        "SSH key configuration references this host: {}",
                                        entry.display()
                                    ),
                                }],
                                detection_methods: vec!["ssh_keys".to_string()],
                                impact_level: ImpactLevel::High,
                            });
                        }
                    }
                }
            }
        }

        Ok(deps)
    }

    fn detect_from_dns_records(hostname: &str) -> Result<Vec<InboundDependency>> {
        let mut deps = Vec::new();

        // Try to query DNS
        let output = std::process::Command::new("dig")
            .args(&[hostname, "+short"])
            .output();

        if let Ok(output) = output {
            let result = String::from_utf8_lossy(&output.stdout);
            for line in result.lines() {
                let ip = line.trim();
                if !ip.is_empty() && ip.chars().all(|c| c.is_numeric() || c == '.') {
                    deps.push(InboundDependency {
                        source_ip: ip.to_string(),
                        source_hostname: Some(hostname.to_string()),
                        confidence: 90,
                        evidence: vec![Evidence {
                            level: EvidenceLevel::High,
                            description: format!("DNS A record resolves to {}", ip),
                        }],
                        detection_methods: vec!["dns_resolution".to_string()],
                        impact_level: ImpactLevel::Critical,
                    });
                }
            }
        }

        Ok(deps)
    }

    fn detect_from_git_config(hostname: &str) -> Result<Vec<InboundDependency>> {
        let mut deps = Vec::new();

        let git_patterns = vec![
            "/home/*/.gitconfig",
            "/root/.gitconfig",
            "/opt/*/.git/config",
            "/var/www/*/.git/config",
        ];

        let host_re = Regex::new(&format!(r"(?i)(?:url|host|origin).*?{}", regex::escape(hostname)))?;

        for pattern in git_patterns {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(&entry) {
                        if host_re.is_match(&content) {
                            deps.push(InboundDependency {
                                source_ip: "unknown".to_string(),
                                source_hostname: None,
                                confidence: 70,
                                evidence: vec![Evidence {
                                    level: EvidenceLevel::Med,
                                    description: format!("Git config references this host: {}", entry.display()),
                                }],
                                detection_methods: vec!["git_config".to_string()],
                                impact_level: ImpactLevel::Medium,
                            });
                        }
                    }
                }
            }
        }

        Ok(deps)
    }

    fn detect_from_nfs_mounts(hostname: &str) -> Result<Vec<InboundDependency>> {
        let mut deps = Vec::new();

        if let Ok(content) = fs::read_to_string("/etc/fstab") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                if trimmed.contains(hostname) && (trimmed.contains("nfs") || trimmed.contains("smb")) {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if let Some(mount_spec) = parts.first() {
                        let ip = mount_spec.split(':').next().unwrap_or(hostname);
                        deps.push(InboundDependency {
                            source_ip: ip.to_string(),
                            source_hostname: Some(hostname.to_string()),
                            confidence: 80,
                            evidence: vec![Evidence {
                                level: EvidenceLevel::High,
                                description: format!("NFS/SMB mount configured in fstab: {}", mount_spec),
                            }],
                            detection_methods: vec!["nfs_mounts".to_string()],
                            impact_level: ImpactLevel::Critical,
                        });
                    }
                }
            }
        }

        Ok(deps)
    }
}
