use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration as StdDuration, Instant};

use crate::config_scanner::ConfigScanner;
use crate::models::*;

pub struct Collector;

static CONFIG_DNS_CACHE: OnceLock<ConfigDnsCache> = OnceLock::new();
static PASSWD_CACHE: OnceLock<HashMap<u32, String>> = OnceLock::new();

type ProcessAttribution = HashMap<u32, (String, u32, String)>;
type ConfigDnsCache = Mutex<Option<(Instant, Vec<DnsName>, Vec<ConfigReference>)>>;

impl Collector {
    pub async fn collect_snapshot() -> Result<ObservationSnapshot> {
        let hostname = Self::get_hostname()?;
        let timestamp = Utc::now();
        let mut probe_statuses = ProbeStatuses::default();

        let (processes, pid_to_process) = match Self::collect_process_inventory() {
            Ok(inventory) => inventory,
            Err(error) => {
                probe_statuses.process_attribution =
                    ProbeStatus::partial(format!("process inventory unavailable: {}", error), 0);
                (Vec::new(), HashMap::new())
            }
        };

        let (listening_services, listening_unavailable) =
            match Self::collect_listening_services(&pid_to_process) {
                Ok(result) => result,
                Err(error) => {
                    probe_statuses.network_sockets = ProbeStatus::failed(error.to_string());
                    (Vec::new(), 0)
                }
            };
        let (network_connections, connection_unavailable) =
            match Self::collect_network_connections(&pid_to_process) {
                Ok(result) => result,
                Err(error) => {
                    probe_statuses.network_sockets = ProbeStatus::failed(error.to_string());
                    (Vec::new(), 0)
                }
            };
        let socket_unavailable = listening_unavailable + connection_unavailable;
        if socket_unavailable > 0 {
            probe_statuses.process_attribution = ProbeStatus::partial(
                format!(
                    "process attribution unavailable for {} sockets",
                    socket_unavailable
                ),
                socket_unavailable,
            );
        }

        let (cron_jobs, cron_unavailable) = Self::collect_cron_jobs()?;
        if cron_unavailable > 0 {
            probe_statuses.cron = ProbeStatus::partial(
                format!("{} cron paths could not be read", cron_unavailable),
                cron_unavailable,
            );
        }
        let systemd_timers = match Self::collect_systemd_timers() {
            Ok(timers) => timers,
            Err(error) => {
                probe_statuses.systemd = ProbeStatus::failed(error.to_string());
                Vec::new()
            }
        };
        let (dns_names, dns_unavailable, config_references) = match Self::collect_dns_names() {
            Ok(result) => result,
            Err(error) => {
                probe_statuses.config_scan = ProbeStatus::failed(error.to_string());
                probe_statuses.dns = ProbeStatus::failed(error.to_string());
                (Vec::new(), 0, Vec::new())
            }
        };
        if dns_unavailable > 0 && probe_statuses.dns.is_complete() {
            probe_statuses.dns = ProbeStatus::partial(
                format!("DNS resolution failed for {} names", dns_unavailable),
                dns_unavailable,
            );
        }

        Ok(ObservationSnapshot {
            timestamp,
            hostname,
            listening_services,
            network_connections,
            processes,
            cron_jobs,
            systemd_timers,
            dns_names,
            config_references,
            probe_statuses,
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

    fn collect_listening_services(
        pid_to_process: &HashMap<u32, (String, u32, String)>,
    ) -> Result<(Vec<ListeningService>, usize)> {
        let mut services = Vec::new();
        let mut unavailable = 0;

        let output = Self::run_socket_probe(&["-tunlp"])?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some((_, port)) = Self::find_endpoints(&parts).first() {
                let pid = Self::extract_pid(parts.last().copied());
                if pid == 0 || !pid_to_process.contains_key(&pid) {
                    unavailable += 1;
                }
                let (process_name, user) = pid_to_process
                    .get(&pid)
                    .map(|(name, _, user)| (name.clone(), user.clone()))
                    .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));

                services.push(ListeningService {
                    port: *port,
                    protocol: Self::socket_protocol(&parts),
                    process_name,
                    pid,
                    user: user.clone(),
                });
            }
        }

        Ok((services, unavailable))
    }

    fn collect_network_connections(
        pid_to_process: &HashMap<u32, (String, u32, String)>,
    ) -> Result<(Vec<NetworkConnection>, usize)> {
        let mut connections = Vec::new();
        let mut unavailable = 0;

        let output = Self::run_socket_probe(&["-tunp"])?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && Self::is_connection_line(&parts) {
                let endpoints = Self::find_endpoints(&parts);
                if let [local, remote, ..] = endpoints.as_slice() {
                    if remote.1 == 0 {
                        continue;
                    }
                    let pid = Self::extract_pid(parts.last().copied());
                    if pid == 0 || !pid_to_process.contains_key(&pid) {
                        unavailable += 1;
                    }
                    let process_name = pid_to_process
                        .get(&pid)
                        .map(|(name, _, _)| name.clone())
                        .unwrap_or_else(|| "unknown".to_string());

                    connections.push(NetworkConnection {
                        local_addr: local.0.clone(),
                        local_port: local.1,
                        remote_addr: remote.0.clone(),
                        remote_port: remote.1,
                        protocol: Self::socket_protocol(&parts),
                        state: Self::socket_state(&parts),
                        pid,
                        process_name,
                    });
                }
            }
        }

        Ok((connections, unavailable))
    }

    fn run_socket_probe(args: &[&str]) -> Result<Output> {
        let ss_result = Command::new("ss").args(args).output();
        if let Ok(output) = ss_result {
            if output.status.success() {
                return Ok(output);
            }
        }

        let netstat = Command::new("netstat")
            .args(args)
            .output()
            .context("Failed to execute ss and netstat")?;
        if netstat.status.success() {
            Ok(netstat)
        } else {
            Err(anyhow!("ss and netstat both failed"))
        }
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
        parts
            .iter()
            .filter_map(|part| Self::parse_addr_port(part))
            .collect()
    }

    fn socket_protocol(parts: &[&str]) -> String {
        parts
            .iter()
            .find_map(|part| match *part {
                "tcp" | "tcp6" => Some("tcp"),
                "udp" | "udp6" => Some("udp"),
                _ => None,
            })
            .or_else(|| {
                if parts.contains(&"UNCONN") {
                    Some("udp")
                } else {
                    Some("tcp")
                }
            })
            .unwrap()
            .to_string()
    }

    fn socket_state(parts: &[&str]) -> String {
        parts
            .iter()
            .find(|part| {
                matches!(
                    **part,
                    "LISTEN" | "ESTAB" | "ESTABLISHED" | "UNCONN" | "CLOSE-WAIT"
                )
            })
            .map(|state| match *state {
                "ESTAB" => "ESTABLISHED",
                other => other,
            })
            .unwrap_or("UNKNOWN")
            .to_string()
    }

    fn is_connection_line(parts: &[&str]) -> bool {
        parts.iter().any(|part| {
            matches!(
                *part,
                "ESTAB" | "ESTABLISHED" | "UNCONN" | "CONNECTED" | "udp" | "udp6"
            )
        })
    }

    fn extract_pid(process_field: Option<&str>) -> u32 {
        let field = match process_field {
            Some(field) => field,
            None => return 0,
        };

        if let Some(pid) = field
            .split("pid=")
            .nth(1)
            .and_then(|value| value.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|value| value.parse().ok())
        {
            return pid;
        }

        field
            .split('/')
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    }

    fn collect_process_inventory() -> Result<(Vec<Process>, ProcessAttribution)> {
        let mut processes = Vec::new();
        let mut pid_to_process = HashMap::new();

        for proc_entry in procfs::process::all_processes()? {
            let process = match proc_entry {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let (Ok(stat), Ok(status)) = (process.stat(), process.status()) {
                let user = Self::username_for_uid(status.ruid);

                processes.push(Process {
                    pid: process.pid() as u32,
                    name: stat.comm.clone(),
                    user: user.clone(),
                    // Command lines frequently contain credentials. The executable name
                    // above is sufficient for dependency attribution.
                    cmdline: String::new(),
                });
                pid_to_process.insert(
                    process.pid() as u32,
                    (stat.comm, process.pid() as u32, user),
                );
            }
        }

        Ok((processes, pid_to_process))
    }

    fn username_for_uid(uid: u32) -> String {
        let users = PASSWD_CACHE.get_or_init(|| {
            fs::read_to_string("/etc/passwd")
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let fields = line.split(':').collect::<Vec<_>>();
                    if fields.len() > 2 {
                        fields[2]
                            .parse::<u32>()
                            .ok()
                            .map(|uid| (uid, fields[0].to_string()))
                    } else {
                        None
                    }
                })
                .collect()
        });
        users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
    }

    fn collect_cron_jobs() -> Result<(Vec<CronJob>, usize)> {
        let mut cron_jobs = Vec::new();
        let mut unavailable = 0;

        Self::collect_cron_file(
            Path::new("/etc/crontab"),
            true,
            &mut cron_jobs,
            &mut unavailable,
        );

        match fs::read_dir("/etc/cron.d") {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        Self::collect_cron_file(&path, true, &mut cron_jobs, &mut unavailable);
                    }
                }
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => unavailable += 1,
            Err(_) => {}
        }

        for (directory, schedule) in [
            ("/etc/cron.daily", "@daily"),
            ("/etc/cron.hourly", "@hourly"),
            ("/etc/cron.weekly", "@weekly"),
            ("/etc/cron.monthly", "@monthly"),
        ] {
            match fs::read_dir(directory) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            cron_jobs.push(CronJob {
                                schedule: schedule.to_string(),
                                command: "[redacted]".to_string(),
                                source: path.display().to_string(),
                            });
                        }
                    }
                }
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => unavailable += 1,
                Err(_) => {}
            }
        }

        for pattern in ["/var/spool/cron/crontabs/*", "/var/spool/cron/*"] {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if entry.is_file() {
                        Self::collect_cron_file(&entry, false, &mut cron_jobs, &mut unavailable);
                    }
                }
            }
        }

        cron_jobs.sort_by(|a, b| a.source.cmp(&b.source));
        Ok((cron_jobs, unavailable))
    }

    fn collect_cron_file(
        path: &Path,
        has_user_field: bool,
        cron_jobs: &mut Vec<CronJob>,
        unavailable: &mut usize,
    ) {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    *unavailable += 1;
                }
                return;
            }
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.first().is_some_and(|field| field.contains('=')) {
                continue;
            }
            let (schedule, command_start) =
                if fields.first().is_some_and(|field| field.starts_with('@')) {
                    if fields.len() < 2 {
                        continue;
                    }
                    (fields[0].to_string(), 1)
                } else {
                    let required = if has_user_field { 7 } else { 6 };
                    if fields.len() < required {
                        continue;
                    }
                    (fields[..5].join(" "), 5 + usize::from(has_user_field))
                };

            if command_start < fields.len() {
                cron_jobs.push(CronJob {
                    schedule,
                    // Cron command bodies may contain credentials or tokens.
                    command: "[redacted]".to_string(),
                    source: path.display().to_string(),
                });
            }
        }
    }

    fn collect_systemd_timers() -> Result<Vec<SystemdTimer>> {
        let mut timers = Vec::new();

        let output = Command::new("systemctl")
            .args(["list-timers", "--all", "--output=json"])
            .output()
            .context("Failed to run systemctl list-timers")?;

        if output.status.success() {
            let json = serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .context("systemd returned invalid JSON")?;
            let timers_array = json
                .as_array()
                .or_else(|| json.get("timers").and_then(|t| t.as_array()))
                .ok_or_else(|| anyhow!("systemd JSON did not contain a timer list"))?;
            for timer_obj in timers_array {
                if let Some(unit) = timer_obj.get("unit").and_then(|u| u.as_str()) {
                    let active = timer_obj
                        .get("active")
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
        } else {
            return Err(anyhow!("systemctl list-timers exited unsuccessfully"));
        }

        Ok(timers)
    }

    fn collect_dns_names() -> Result<(Vec<DnsName>, usize, Vec<ConfigReference>)> {
        let cache = CONFIG_DNS_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache.lock() {
            if let Some((timestamp, names, references)) = guard.as_ref() {
                if timestamp.elapsed() < StdDuration::from_secs(300) {
                    return Ok((names.clone(), 0, references.clone()));
                }
            }
        }

        let mut names = Vec::new();
        let mut unavailable = 0;

        let config_refs = ConfigScanner::scan()?;
        let timestamp = Utc::now();

        let mut seen = std::collections::HashSet::new();

        for config_ref in &config_refs {
            if seen.insert(config_ref.hostname.clone()) {
                use std::net::ToSocketAddrs;

                let ip_addresses = match format!("{}:80", config_ref.hostname).to_socket_addrs() {
                    Ok(addrs) => addrs.map(|addr| addr.ip().to_string()).collect(),
                    Err(_) => vec![],
                };
                if ip_addresses.is_empty() {
                    unavailable += 1;
                }

                names.push(DnsName {
                    hostname: config_ref.hostname.clone(),
                    ip_addresses,
                    timestamp,
                });
            }
        }

        if let Ok(mut guard) = cache.lock() {
            *guard = Some((Instant::now(), names.clone(), config_refs.clone()));
        }
        Ok((names, unavailable, config_refs))
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
        assert_eq!(
            Collector::extract_pid(Some("users:((\"nginx\",pid=1234,fd=7))")),
            1234
        );
        assert_eq!(Collector::extract_pid(Some("1234/nginx")), 1234);
        assert_eq!(Collector::extract_pid(None), 0);
    }

    #[test]
    fn finds_local_and_remote_ss_endpoints() {
        let fields = ["tcp", "ESTAB", "0", "127.0.0.1:42000", "[::1]:5432"];
        assert_eq!(
            Collector::find_endpoints(&fields),
            vec![("127.0.0.1".to_string(), 42000), ("::1".to_string(), 5432),]
        );
    }

    #[test]
    fn accepts_modern_ss_state_first_format() {
        let fields = "ESTAB 0 0 127.0.0.1:36886 127.0.0.1:55059";
        let parts: Vec<&str> = fields.split_whitespace().collect();
        assert!(parts.contains(&"ESTAB"));
        assert_eq!(Collector::find_endpoints(&parts).len(), 2);
    }

    #[test]
    fn parses_cron_schedule_without_persisting_command_body() {
        let path =
            std::env::temp_dir().join(format!("screamless-cron-test-{}", std::process::id()));
        std::fs::write(&path, "0 2 * * * root /usr/bin/backup --token=secret\n").unwrap();
        let mut jobs = Vec::new();
        let mut unavailable = 0;
        Collector::collect_cron_file(&path, true, &mut jobs, &mut unavailable);
        let _ = std::fs::remove_file(&path);

        assert_eq!(unavailable, 0);
        assert_eq!(jobs[0].schedule, "0 2 * * *");
        assert_eq!(jobs[0].command, "[redacted]");
    }

    #[test]
    fn recognizes_udp_socket_state_and_protocol() {
        let fields = ["UNCONN", "0", "0", "127.0.0.1:5353", "0.0.0.0:*"];
        assert!(Collector::is_connection_line(&fields));
        assert_eq!(Collector::socket_protocol(&fields), "udp");
        assert_eq!(Collector::socket_state(&fields), "UNCONN");
    }
}
