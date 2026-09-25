use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::process::Command;

use crate::models::*;
use crate::config_scanner::ConfigScanner;

pub struct Collector;

impl Collector {
    pub async fn collect_snapshot() -> Result<ObservationSnapshot> {
        let hostname = Self::get_hostname()?;
        let timestamp = Utc::now();

        Ok(ObservationSnapshot {
            timestamp,
            hostname,
            listening_services: Self::collect_listening_services()?,
            network_connections: Self::collect_network_connections()?,
            processes: Self::collect_processes()?,
            cron_jobs: Self::collect_cron_jobs()?,
            systemd_timers: Self::collect_systemd_timers()?,
            dns_names: Self::collect_dns_names()?,
        })
    }

    fn get_hostname() -> Result<String> {
        fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                Command::new("hostname")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .context("Failed to get hostname")
            })
            .context("Could not determine hostname")
    }

    fn collect_listening_services() -> Result<Vec<ListeningService>> {
        let mut services = Vec::new();

        let pid_to_process = Self::build_pid_to_process_map()?;

        let output = Command::new("ss")
            .args(&["-tlnp"])
            .output()
            .or_else(|_| Command::new("netstat").args(&["-tlnp"]).output())
            .context("Failed to run ss or netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some((_, port)) = Self::find_endpoints(&parts).first() {
                let pid = Self::extract_pid(parts.last().copied());
                let (process_name, user) = pid_to_process
                    .get(&pid)
                    .map(|(name, _, user)| (name.clone(), user.clone()))
                    .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));

                services.push(ListeningService {
                    port: *port,
                    protocol: "tcp".to_string(),
                    process_name,
                    pid,
                    user,
                });
            }
        }

        Ok(services)
    }

    fn collect_network_connections() -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();

        let pid_to_process = Self::build_pid_to_process_map()?;

        let output = Command::new("ss")
            .args(&["-tnp"])
            .output()
            .or_else(|_| Command::new("netstat").args(&["-tnp"]).output())
            .context("Failed to run ss or netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && (parts[0] == "tcp" || parts[0] == "tcp6") {
                if parts[1].contains("ESTAB") || line.contains("ESTABLISHED") {
                    let endpoints = Self::find_endpoints(&parts);
                    if let [local, remote, ..] = endpoints.as_slice() {
                        let pid = Self::extract_pid(parts.last().copied());
                        let process_name = pid_to_process
                            .get(&pid)
                            .map(|(name, _, _)| name.clone())
                            .unwrap_or_else(|| "unknown".to_string());

                        connections.push(NetworkConnection {
                            local_addr: local.0.clone(),
                            local_port: local.1,
                            remote_addr: remote.0.clone(),
                            remote_port: remote.1,
                            protocol: "tcp".to_string(),
                            state: "ESTABLISHED".to_string(),
                            pid,
                            process_name,
                        });
                    }
                }
            }
        }

        Ok(connections)
    }

    fn parse_addr_port(addr_port: &str) -> Option<(String, u16)> {
        if let Some(last_colon) = addr_port.rfind(':') {
            let addr = addr_port[..last_colon]
                .strip_prefix('[')
                .and_then(|addr| addr.strip_suffix(']'))
                .unwrap_or(&addr_port[..last_colon])
                .to_string();
            let port = addr_port[last_colon + 1..].parse::<u16>().ok()?;
            Some((addr, port))
        } else {
            None
        }
    }

    fn find_endpoints(parts: &[&str]) -> Vec<(String, u16)> {
        parts.iter()
            .filter_map(|part| Self::parse_addr_port(part))
            .collect()
    }

    fn extract_pid(process_field: Option<&str>) -> u32 {
        let field = match process_field {
            Some(field) => field,
            None => return 0,
        };

        if let Some(pid) = field.split("pid=").nth(1)
            .and_then(|value| value.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|value| value.parse().ok())
        {
            return pid;
        }

        field.split('/').next().and_then(|value| value.parse().ok()).unwrap_or(0)
    }

    fn collect_processes() -> Result<Vec<Process>> {
        let mut processes = Vec::new();

        for proc_entry in procfs::process::all_processes()? {
            let process = match proc_entry {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let (Ok(stat), Ok(status)) = (process.stat(), process.status()) {
                let cmdline = process.cmdline()
                    .unwrap_or_default()
                    .join(" ");

                let user = status.ruid.to_string();

                processes.push(Process {
                    pid: process.pid() as u32,
                    name: stat.comm.clone(),
                    user,
                    cmdline,
                });
            }
        }

        Ok(processes)
    }

    fn collect_cron_jobs() -> Result<Vec<CronJob>> {
        let mut cron_jobs = Vec::new();

        let cron_dirs = vec![
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.monthly",
            "/etc/cron.weekly",
        ];

        for dir in cron_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(path) = entry.path().canonicalize() {
                        if path.is_file() {
                            if let Ok(content) = fs::read_to_string(&path) {
                                for line in content.lines() {
                                    let trimmed = line.trim();
                                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                        cron_jobs.push(CronJob {
                                            schedule: "system".to_string(),
                                            command: trimmed.to_string(),
                                            source: path.display().to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        cron_jobs.sort_by(|a, b| a.source.cmp(&b.source));
        Ok(cron_jobs)
    }

    fn collect_systemd_timers() -> Result<Vec<SystemdTimer>> {
        let mut timers = Vec::new();

        let output = Command::new("systemctl")
            .args(&["list-timers", "--all", "--output=json"])
            .output()
            .context("Failed to run systemctl list-timers")?;

        if output.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                let timers_array = json.as_array()
                    .or_else(|| json.get("timers").and_then(|t| t.as_array()));
                if let Some(timers_array) = timers_array {
                    for timer_obj in timers_array {
                        if let Some(unit) = timer_obj.get("unit").and_then(|u| u.as_str()) {
                            let active = timer_obj.get("active")
                                .and_then(|a| a.as_str())
                                .map(|a| a == "active")
                                .unwrap_or(true);
                            timers.push(SystemdTimer {
                                name: unit.replace(".timer", ""),
                                unit: unit.to_string(),
                                enabled: true,
                                active,
                            });
                        }
                    }
                }
            }
        }

        Ok(timers)
    }

    fn build_pid_to_process_map() -> Result<HashMap<u32, (String, u32, String)>> {
        let mut map = HashMap::new();

        for proc_entry in procfs::process::all_processes()? {
            let process = match proc_entry {
                Ok(p) => p,
                Err(_) => continue,
            };

            let pid = process.pid() as u32;
            let stat = process.stat().ok();
            let status = process.status().ok();

            let name = stat
                .map(|s| s.comm.clone())
                .unwrap_or_else(|| "unknown".to_string());

            let user = status
                .map(|s| s.ruid.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            map.insert(pid, (name, pid, user));
        }

        Ok(map)
    }

    fn collect_dns_names() -> Result<Vec<DnsName>> {
        let mut names = Vec::new();

        let config_refs = ConfigScanner::scan().unwrap_or_default();
        let timestamp = Utc::now();

        let mut seen = std::collections::HashSet::new();

        for config_ref in config_refs {
            if seen.insert(config_ref.hostname.clone()) {
                use std::net::ToSocketAddrs;

                let ip_addresses = match format!("{}:80", config_ref.hostname)
                    .to_socket_addrs()
                {
                    Ok(addrs) => addrs
                        .map(|addr| addr.ip().to_string())
                        .collect(),
                    Err(_) => vec![],
                };

                names.push(DnsName {
                    hostname: config_ref.hostname,
                    ip_addresses,
                    timestamp,
                });
            }
        }

        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::Collector;

    #[test]
    fn parses_ss_ipv6_endpoint_without_brackets() {
        assert_eq!(
            Collector::parse_addr_port("[2001:db8::1]:443"),
            Some(("2001:db8::1".to_string(), 443))
        );
    }

    #[test]
    fn extracts_pid_from_ss_process_metadata() {
        assert_eq!(Collector::extract_pid(Some("users:((\"nginx\",pid=1234,fd=7))")), 1234);
        assert_eq!(Collector::extract_pid(Some("1234/nginx")), 1234);
        assert_eq!(Collector::extract_pid(None), 0);
    }

    #[test]
    fn finds_local_and_remote_ss_endpoints() {
        let fields = ["tcp", "ESTAB", "0", "127.0.0.1:42000", "[::1]:5432"];
        assert_eq!(Collector::find_endpoints(&fields), vec![
            ("127.0.0.1".to_string(), 42000),
            ("::1".to_string(), 5432),
        ]);
    }
}
