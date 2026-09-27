use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use crate::config_scanner::ConfigScanner;
use crate::models::*;

pub struct Collector;

static CONFIG_DNS_CACHE: OnceLock<ConfigDnsCache> = OnceLock::new();
static PASSWD_CACHE: OnceLock<HashMap<u32, String>> = OnceLock::new();

type ProcessAttribution = HashMap<u32, (String, u32, String)>;
type ConfigDnsCache = Mutex<
    Option<(
        Instant,
        Vec<DnsName>,
        usize,
        Vec<ConfigReference>,
        ConfigScanAudit,
    )>,
>;
type ProcessInventory = (
    Vec<Process>,
    ProcessAttribution,
    Vec<SoftwareInventory>,
    usize,
);

const SLOW_REFRESH_INTERVAL: StdDuration =
    StdDuration::from_secs(SLOW_INVENTORY_REFRESH_INTERVAL_SECONDS as u64);
const SLOW_REFRESH_RETRY_INTERVAL: StdDuration = StdDuration::from_secs(5 * 60);
const SMALL_PROBE_TIMEOUT: StdDuration = StdDuration::from_secs(3);
const INVENTORY_PROBE_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const SMALL_PROBE_OUTPUT_LIMIT: usize = 1024 * 1024;
const SOCKET_PROBE_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const DNS_LOOKUP_TIMEOUT: StdDuration = StdDuration::from_secs(3);
const DNS_COLLECTION_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const DNS_LOOKUP_BATCH_SIZE: usize = 16;
const DNS_LOOKUP_LIMIT: usize = 1024;

/// State carried between observations so slow-changing inventory is refreshed
/// hourly instead of being recollected on every network/process sample.
#[derive(Default)]
pub struct CollectionState {
    last_slow_refresh: Option<Instant>,
    software: Vec<SoftwareInventory>,
    cron_jobs: Vec<CronJob>,
    systemd_timers: Vec<SystemdTimer>,
    dns_names: Vec<DnsName>,
    config_references: Vec<ConfigReference>,
    config_scan_audit: Option<ConfigScanAudit>,
    host_identity: HostIdentity,
    slow_probe_statuses: ProbeStatuses,
}

impl Collector {
    pub async fn collect_snapshot() -> Result<ObservationSnapshot> {
        let mut state = CollectionState::default();
        Self::collect_snapshot_with_state(&mut state).await
    }

    pub async fn collect_snapshot_with_state(
        state: &mut CollectionState,
    ) -> Result<ObservationSnapshot> {
        let hostname = Self::get_hostname()?;
        let timestamp = Utc::now();
        let slow_refresh_interval = Self::slow_refresh_interval(&state.slow_probe_statuses);
        let refresh_slow = state
            .last_slow_refresh
            .map_or(true, |last| last.elapsed() >= slow_refresh_interval);
        let mut probe_statuses = if refresh_slow {
            ProbeStatuses::default()
        } else {
            state.slow_probe_statuses.clone()
        };
        // These probes run for every snapshot. Carrying a previous failure
        // forward would make a recovered probe look unhealthy indefinitely.
        Self::reset_fast_probe_statuses(&mut probe_statuses);

        let (
            processes,
            pid_to_process,
            observed_software,
            process_inventory_unavailable,
            process_inventory_error,
        ) = match Self::collect_process_inventory(refresh_slow) {
            Ok((processes, pid_to_process, software, unavailable)) => {
                (processes, pid_to_process, software, unavailable, None)
            }
            Err(error) => (
                Vec::new(),
                HashMap::new(),
                Vec::new(),
                1,
                Some(error.to_string()),
            ),
        };
        if refresh_slow {
            state.software = observed_software;
        }

        let (listening_services, listening_unavailable, listening_malformed) =
            match Self::collect_listening_services(&pid_to_process) {
                Ok(result) => result,
                Err(error) => {
                    probe_statuses.network_sockets = ProbeStatus::failed(error.to_string());
                    (Vec::new(), 0, 0)
                }
            };
        let (network_connections, connection_unavailable, connection_malformed) =
            match Self::collect_network_connections(&pid_to_process) {
                Ok(result) => result,
                Err(error) => {
                    probe_statuses.network_sockets = ProbeStatus::failed(error.to_string());
                    (Vec::new(), 0, 0)
                }
            };
        let malformed_socket_rows = listening_malformed + connection_malformed;
        if malformed_socket_rows > 0 && probe_statuses.network_sockets.is_complete() {
            probe_statuses.network_sockets = ProbeStatus::partial(
                format!("unable to parse {} socket row(s)", malformed_socket_rows),
                malformed_socket_rows,
            );
        }
        let socket_unavailable = listening_unavailable + connection_unavailable;
        if let Some(status) = Self::process_attribution_status(
            process_inventory_unavailable,
            socket_unavailable,
            process_inventory_error.as_deref(),
        ) {
            probe_statuses.process_attribution = status;
        }

        if refresh_slow {
            match Self::collect_cron_jobs() {
                Ok((cron_jobs, cron_unavailable)) => {
                    state.cron_jobs = cron_jobs;
                    if cron_unavailable > 0 {
                        probe_statuses.cron = ProbeStatus::partial(
                            format!("{} cron paths could not be read", cron_unavailable),
                            cron_unavailable,
                        );
                    }
                }
                Err(error) => probe_statuses.cron = ProbeStatus::failed(error.to_string()),
            }
        }
        if refresh_slow {
            match Self::collect_systemd_timers() {
                Ok(timers) => state.systemd_timers = timers,
                Err(error) => probe_statuses.systemd = ProbeStatus::failed(error.to_string()),
            }
            match Self::collect_dns_names().await {
                Ok((dns_names, dns_unavailable, config_references, config_scan_audit)) => {
                    state.dns_names = dns_names;
                    state.config_references = config_references;
                    if let Some(status) = Self::config_scan_probe_status(&config_scan_audit) {
                        probe_statuses.config_scan = status;
                    }
                    state.config_scan_audit = Some(config_scan_audit);
                    if dns_unavailable > 0 {
                        probe_statuses.dns = ProbeStatus::partial(
                            format!(
                                "DNS unavailable or not scanned for {} names",
                                dns_unavailable
                            ),
                            dns_unavailable,
                        );
                    }
                }
                Err(error) => {
                    probe_statuses.config_scan = ProbeStatus::failed(error.to_string());
                    probe_statuses.dns = ProbeStatus::failed(error.to_string());
                }
            }
            let (host_identity, host_identity_status) = Self::collect_host_identity(&hostname);
            state.host_identity = host_identity;
            probe_statuses.host_identity = host_identity_status;
            state.slow_probe_statuses = probe_statuses.clone();
            state.last_slow_refresh = Some(Instant::now());
        }
        Ok(ObservationSnapshot {
            timestamp,
            hostname,
            host_identity: if refresh_slow {
                state.host_identity.clone()
            } else {
                HostIdentity::default()
            },
            listening_services,
            network_connections,
            processes,
            cron_jobs: if refresh_slow {
                state.cron_jobs.clone()
            } else {
                Vec::new()
            },
            systemd_timers: if refresh_slow {
                state.systemd_timers.clone()
            } else {
                Vec::new()
            },
            slow_inventory_refreshed: Some(refresh_slow),
            dns_names: if refresh_slow {
                state.dns_names.clone()
            } else {
                Vec::new()
            },
            config_references: if refresh_slow {
                state.config_references.clone()
            } else {
                Vec::new()
            },
            config_scan_audit: if refresh_slow {
                state.config_scan_audit.clone()
            } else {
                None
            },
            software: if refresh_slow {
                state.software.clone()
            } else {
                Vec::new()
            },
            sampling_interval_seconds: None,
            privileges: Self::current_privilege_level(),
            probe_statuses,
        })
    }

    fn get_hostname() -> Result<String> {
        fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                let executable = Self::trusted_command_path("hostname")
                    .ok_or_else(|| anyhow!("No trusted hostname utility found"))?;
                Self::run_bounded_command(
                    executable,
                    &[],
                    SMALL_PROBE_TIMEOUT,
                    SMALL_PROBE_OUTPUT_LIMIT,
                )
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .context("Failed to get hostname")
            })
            .context("Could not determine hostname")
    }

    fn current_privilege_level() -> String {
        let uid = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|value| value.parse::<u32>().ok())
            });
        if uid == Some(0) {
            "full".to_string()
        } else {
            "restricted".to_string()
        }
    }

    fn slow_refresh_interval(statuses: &ProbeStatuses) -> StdDuration {
        if statuses.cron.is_complete()
            && statuses.systemd.is_complete()
            && statuses.config_scan.is_complete()
            && statuses.dns.is_complete()
            && statuses.host_identity.is_complete()
        {
            SLOW_REFRESH_INTERVAL
        } else {
            SLOW_REFRESH_RETRY_INTERVAL
        }
    }

    fn reset_fast_probe_statuses(statuses: &mut ProbeStatuses) {
        statuses.network_sockets = ProbeStatus::complete();
        statuses.process_attribution = ProbeStatus::complete();
    }

    fn process_attribution_status(
        unavailable_process_entries: usize,
        unavailable_sockets: usize,
        inventory_error: Option<&str>,
    ) -> Option<ProbeStatus> {
        let unavailable = unavailable_process_entries + unavailable_sockets;
        if unavailable == 0 {
            return None;
        }

        let details = match inventory_error {
            Some(error) => format!("process inventory unavailable: {}", error),
            None => format!(
                "process inventory unavailable for {} entry/entries and process attribution unavailable for {} socket(s)",
                unavailable_process_entries, unavailable_sockets
            ),
        };
        Some(ProbeStatus::partial(details, unavailable))
    }

    fn collect_host_identity(hostname: &str) -> (HostIdentity, ProbeStatus) {
        let short_hostname = hostname.split('.').next().unwrap_or(hostname).to_string();
        let fqdn = Self::command_text("hostname", &["--fqdn"])
            .filter(|value| value.contains('.'))
            .or_else(|| hostname.contains('.').then(|| hostname.to_string()));
        let (interface_addresses, status) = Self::interface_addresses();
        let ipv4_addresses = interface_addresses
            .iter()
            .filter(|address| address.parse::<std::net::Ipv4Addr>().is_ok())
            .cloned()
            .collect();
        let ipv6_addresses = interface_addresses
            .iter()
            .filter(|address| address.parse::<std::net::Ipv6Addr>().is_ok())
            .cloned()
            .collect();
        let dns_aliases = Self::hosts_aliases(hostname, &interface_addresses);

        (
            HostIdentity {
                hostname: hostname.to_string(),
                fqdn,
                short_hostname,
                host_uuid: Self::read_identity_file("/sys/class/dmi/id/product_uuid"),
                machine_id: Self::read_identity_file("/etc/machine-id")
                    .or_else(|| Self::read_identity_file("/var/lib/dbus/machine-id")),
                cloud_instance_id: [
                    "/var/lib/cloud/instance/instance-id",
                    "/var/lib/cloud/data/instance-id",
                ]
                .into_iter()
                .find_map(Self::read_identity_file),
                ipv4_addresses,
                ipv6_addresses,
                vip_addresses: Vec::new(),
                interface_addresses,
                dns_aliases,
                // Container addresses require a container-runtime API or namespace
                // inspection and are intentionally left empty when unavailable.
                container_addresses: Vec::new(),
            },
            status,
        )
    }

    fn read_identity_file(path: &str) -> Option<String> {
        let value = fs::read_to_string(path).ok()?.trim().to_string();
        (!value.is_empty()).then_some(value)
    }

    fn command_text(command: &str, args: &[&str]) -> Option<String> {
        let executable = Self::trusted_command_path(command)?;
        let output = Self::run_bounded_command(
            executable,
            args,
            SMALL_PROBE_TIMEOUT,
            SMALL_PROBE_OUTPUT_LIMIT,
        )
        .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!value.is_empty()).then_some(value)
    }

    fn run_bounded_command(
        executable: std::path::PathBuf,
        args: &[&str],
        timeout: StdDuration,
        output_limit: usize,
    ) -> io::Result<Output> {
        let mut command = Command::new(executable);
        command
            .args(args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "child stdout pipe was not created")
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "child stderr pipe was not created")
        })?;
        let stdout_reader = thread::spawn(move || Self::read_limited(stdout, output_limit));
        let stderr_reader = thread::spawn(move || Self::read_limited(stderr, output_limit));

        let started = Instant::now();
        let (status, timed_out) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (status, false),
                Ok(None) => {}
                Err(error) => {
                    let _ = Self::kill_command_process_group(&mut child);
                    let _ = child.wait();
                    return Err(error);
                }
            }
            if started.elapsed() >= timeout {
                if let Err(error) = Self::kill_command_process_group(&mut child) {
                    let _ = child.wait();
                    return Err(error);
                }
                break (child.wait()?, true);
            }
            thread::sleep(StdDuration::from_millis(10));
        };

        // A utility may exit after spawning descendants that inherited its
        // output pipes. They belong to this bounded invocation; terminate the
        // process group before joining readers so they cannot hang collection.
        let _ = Self::kill_command_process_group(&mut child);

        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "stdout reader thread panicked"))??;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "stderr reader thread panicked"))??;

        if timed_out {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "trusted utility exceeded its execution deadline",
            ));
        }
        if stdout_truncated || stderr_truncated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trusted utility output exceeded the configured size limit",
            ));
        }

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn kill_command_process_group(child: &mut std::process::Child) -> io::Result<()> {
        #[cfg(unix)]
        {
            let process_group = -(child.id() as libc::pid_t);
            // SAFETY: kill is called with the process group created for this
            // child by CommandExt::process_group(0); no memory is accessed.
            let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
            if result == 0 {
                Ok(())
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
        #[cfg(not(unix))]
        {
            child.kill()
        }
    }

    fn read_limited<R: Read>(mut reader: R, limit: usize) -> io::Result<(Vec<u8>, bool)> {
        let mut output = Vec::with_capacity(limit.min(8192));
        let mut buffer = [0; 8192];
        let mut truncated = false;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(output.len());
            let retained = read.min(remaining);
            output.extend_from_slice(&buffer[..retained]);
            truncated |= retained != read;
        }
        Ok((output, truncated))
    }

    fn trusted_command_path(command: &str) -> Option<std::path::PathBuf> {
        if command.is_empty()
            || !command
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return None;
        }

        ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
            .iter()
            .map(|directory| std::path::Path::new(directory).join(command))
            .find_map(|candidate| {
                let executable = fs::canonicalize(candidate).ok()?;
                let metadata = fs::metadata(&executable).ok()?;
                if !metadata.is_file() {
                    return None;
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.uid() != 0
                        || metadata.mode() & 0o022 != 0
                        || metadata.mode() & 0o111 == 0
                    {
                        return None;
                    }
                    let mut directory = executable.parent();
                    while let Some(path) = directory {
                        let directory_metadata = fs::metadata(path).ok()?;
                        if !directory_metadata.is_dir()
                            || directory_metadata.uid() != 0
                            || directory_metadata.mode() & 0o022 != 0
                        {
                            return None;
                        }
                        if path == std::path::Path::new("/") {
                            break;
                        }
                        directory = path.parent();
                    }
                }

                Some(executable)
            })
    }

    fn interface_addresses() -> (Vec<String>, ProbeStatus) {
        if let Some(output) = Self::command_text("ip", &["-j", "-o", "address", "show"]) {
            if let Some(addresses) = Self::parse_interface_addresses_json(&output) {
                return (addresses, ProbeStatus::complete());
            }
        }

        let hostname_output = Self::command_text("hostname", &["-I"]);
        Self::parse_hostname_interface_addresses(hostname_output.as_deref())
    }

    fn parse_interface_addresses_json(output: &str) -> Option<Vec<String>> {
        let interfaces = serde_json::from_str::<serde_json::Value>(output).ok()?;
        let addresses = interfaces
            .as_array()?
            .iter()
            .flat_map(|interface| interface.get("addr_info"))
            .filter_map(|value| value.as_array())
            .flatten()
            .filter_map(|address| address.get("local").and_then(|value| value.as_str()))
            .filter(|address| address.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string)
            .collect::<Vec<_>>();
        (!addresses.is_empty()).then_some(addresses)
    }

    fn parse_hostname_interface_addresses(output: Option<&str>) -> (Vec<String>, ProbeStatus) {
        match output {
            Some(value) => {
                let addresses = value
                    .split_whitespace()
                    .filter(|address| address.parse::<std::net::IpAddr>().is_ok())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if addresses.is_empty() {
                    (
                        addresses,
                        ProbeStatus::partial("no interface addresses were reported", 1),
                    )
                } else {
                    (addresses, ProbeStatus::complete())
                }
            }
            None => (
                Vec::new(),
                ProbeStatus::failed("unable to collect interface addresses using ip or hostname"),
            ),
        }
    }

    fn hosts_aliases(hostname: &str, interface_addresses: &[String]) -> Vec<String> {
        fs::read_to_string("/etc/hosts")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split('#').next())
            .flat_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                let Some(address) = fields.first() else {
                    return Vec::new();
                };
                let local_address = interface_addresses.iter().any(|local| local == address);
                let names_local_host = fields
                    .iter()
                    .skip(1)
                    .any(|name| name.eq_ignore_ascii_case(hostname));
                if local_address || names_local_host {
                    fields
                        .iter()
                        .skip(1)
                        .map(|name| (*name).to_string())
                        .collect()
                } else {
                    Vec::new()
                }
            })
            .filter(|alias| !alias.eq_ignore_ascii_case(hostname) && alias != "localhost")
            .collect()
    }

    fn collect_listening_services(
        pid_to_process: &HashMap<u32, (String, u32, String)>,
    ) -> Result<(Vec<ListeningService>, usize, usize)> {
        let mut services = Vec::new();
        let mut unavailable = 0;
        let mut malformed = 0;

        let output = Self::run_socket_probe(&["-tunlp"])?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !Self::is_socket_record(&parts) {
                continue;
            }
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
            } else {
                malformed += 1;
            }
        }

        Ok((services, unavailable, malformed))
    }

    fn collect_network_connections(
        pid_to_process: &HashMap<u32, (String, u32, String)>,
    ) -> Result<(Vec<NetworkConnection>, usize, usize)> {
        let output = Self::run_socket_probe(&["-tunp"])?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_network_connections_output(
            &stdout,
            pid_to_process,
        ))
    }

    fn parse_network_connections_output(
        stdout: &str,
        pid_to_process: &HashMap<u32, (String, u32, String)>,
    ) -> (Vec<NetworkConnection>, usize, usize) {
        let mut connections = Vec::new();
        let mut unavailable = 0;
        let mut malformed = 0;

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4
                && Self::is_socket_record(&parts)
                && Self::is_connection_line(&parts)
            {
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
                } else if Self::is_malformed_connection_row(&parts) {
                    malformed += 1;
                }
            }
        }

        (connections, unavailable, malformed)
    }

    fn run_socket_probe(args: &[&str]) -> Result<Output> {
        if let Some(ss) = Self::trusted_command_path("ss") {
            if let Ok(output) = Self::run_bounded_command(
                ss,
                args,
                INVENTORY_PROBE_TIMEOUT,
                SOCKET_PROBE_OUTPUT_LIMIT,
            ) {
                if output.status.success() {
                    return Ok(output);
                }
            }
        }

        let netstat = Self::trusted_command_path("netstat")
            .ok_or_else(|| anyhow!("No trusted ss or netstat utility found"))?;
        let netstat = Self::run_bounded_command(
            netstat,
            args,
            INVENTORY_PROBE_TIMEOUT,
            SOCKET_PROBE_OUTPUT_LIMIT,
        )
        .context("Failed to execute trusted ss and netstat utilities")?;
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
            .find_map(|part| Self::canonical_socket_state(part))
            .unwrap_or("UNKNOWN")
            .to_string()
    }

    fn canonical_socket_state(state: &str) -> Option<&'static str> {
        let state = state.to_ascii_uppercase().replace('_', "-");
        Some(match state.as_str() {
            "LISTEN" => "LISTEN",
            "ESTAB" | "ESTABLISHED" => "ESTABLISHED",
            "SYN-SENT" => "SYN-SENT",
            "SYN-RECV" => "SYN-RECV",
            "FIN-WAIT-1" | "FIN-WAIT1" => "FIN-WAIT-1",
            "FIN-WAIT-2" | "FIN-WAIT2" => "FIN-WAIT-2",
            "TIME-WAIT" => "TIME-WAIT",
            "CLOSE" => "CLOSE",
            "CLOSE-WAIT" => "CLOSE-WAIT",
            "LAST-ACK" => "LAST-ACK",
            "CLOSING" => "CLOSING",
            "NEW-SYN-RECV" => "NEW-SYN-RECV",
            "UNCONN" => "UNCONN",
            "CONNECTED" => "CONNECTED",
            _ => return None,
        })
    }

    fn is_connection_line(parts: &[&str]) -> bool {
        parts.iter().any(|part| {
            Self::canonical_socket_state(part).is_some_and(|state| state != "LISTEN")
                || matches!(*part, "udp" | "udp6")
        })
    }

    fn is_malformed_connection_row(parts: &[&str]) -> bool {
        Self::is_socket_record(parts)
            && Self::is_connection_line(parts)
            && Self::find_endpoints(parts).len() < 2
            && Self::socket_state(parts) != "UNCONN"
    }

    fn is_socket_record(parts: &[&str]) -> bool {
        parts.iter().take(2).any(|part| {
            matches!(
                *part,
                "tcp"
                    | "tcp6"
                    | "udp"
                    | "udp6"
                    | "udplite"
                    | "udplite6"
                    | "raw"
                    | "raw6"
                    | "LISTEN"
                    | "ESTAB"
                    | "ESTABLISHED"
                    | "SYN-SENT"
                    | "SYN-RECV"
                    | "FIN-WAIT-1"
                    | "FIN-WAIT-2"
                    | "TIME-WAIT"
                    | "CLOSE"
                    | "CLOSE-WAIT"
                    | "LAST-ACK"
                    | "CLOSING"
                    | "NEW-SYN-RECV"
                    | "UNCONN"
                    | "CONNECTED"
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

    fn collect_process_inventory(include_software: bool) -> Result<ProcessInventory> {
        let mut processes = Vec::new();
        let mut pid_to_process = HashMap::new();
        let mut software_candidates = HashMap::<String, (u32, Option<String>)>::new();
        let mut unavailable = 0;

        for proc_entry in procfs::process::all_processes()? {
            let process = match proc_entry {
                Ok(p) => p,
                Err(error) => {
                    unavailable += usize::from(Self::process_error_requires_partial(&error));
                    continue;
                }
            };

            let (stat, status) = match (process.stat(), process.status()) {
                (Ok(stat), Ok(status)) => (stat, status),
                (stat, status) => {
                    unavailable += usize::from(
                        stat.as_ref()
                            .err()
                            .is_some_and(Self::process_error_requires_partial)
                            || status
                                .as_ref()
                                .err()
                                .is_some_and(Self::process_error_requires_partial),
                    );
                    continue;
                }
            };
            let user = Self::username_for_uid(status.ruid);
            let process_name = stat.comm.clone();

            processes.push(Process {
                pid: process.pid() as u32,
                name: process_name.clone(),
                user: user.clone(),
                // Command lines frequently contain credentials. The executable name
                // above is sufficient for dependency attribution.
                cmdline: String::new(),
            });
            pid_to_process.insert(
                process.pid() as u32,
                (process_name.clone(), process.pid() as u32, user),
            );
            if include_software && Self::is_known_software(&process_name) {
                let executable = fs::read_link(format!("/proc/{}/exe", process.pid()))
                    .ok()
                    .map(|path| path.display().to_string());
                let candidate = software_candidates
                    .entry(Self::software_name(&process_name))
                    .or_insert((process.pid() as u32, None));
                if executable.is_some() && candidate.1.is_none() {
                    *candidate = (process.pid() as u32, executable);
                }
            }
        }

        let software = software_candidates
            .into_iter()
            .map(|(name, (pid, executable))| Self::collect_software_version(name, pid, executable))
            .collect();

        Ok((processes, pid_to_process, software, unavailable))
    }

    fn process_error_requires_partial(error: &procfs::ProcError) -> bool {
        match error {
            procfs::ProcError::NotFound(_) => false,
            procfs::ProcError::Io(error, _) if error.kind() == io::ErrorKind::NotFound => false,
            _ => true,
        }
    }

    fn is_known_software(process_name: &str) -> bool {
        let name = process_name.to_ascii_lowercase();
        match name.as_str() {
            "node" | "nodejs" | "python" | "python3" | "gunicorn" | "uwsgi" | "caddy"
            | "traefik" | "nginx" | "apache2" | "httpd" | "haproxy" | "php" | "postgres"
            | "mysqld" | "mariadbd" | "mongod" | "mongos" | "redis-server" | "memcached"
            | "sqlservr" => true,
            _ => name.starts_with("python3.") || name.starts_with("php-fpm"),
        }
    }

    fn software_name(process_name: &str) -> String {
        let name = process_name.to_ascii_lowercase();
        if name.starts_with("python3.") || name == "python3" || name == "python" {
            "python".to_string()
        } else if name.starts_with("php-fpm") || name == "php" {
            "php".to_string()
        } else if name == "nodejs" {
            "node".to_string()
        } else if name == "apache2" || name == "httpd" {
            "apache".to_string()
        } else if name == "postgres" {
            "postgresql".to_string()
        } else if name == "mysqld" {
            "mysql-compatible database".to_string()
        } else if name == "mariadbd" {
            "mariadb".to_string()
        } else if name == "mongod" || name == "mongos" {
            "mongodb".to_string()
        } else if name == "redis-server" {
            "redis".to_string()
        } else if name == "sqlservr" {
            "sql-server".to_string()
        } else {
            name
        }
    }

    fn collect_software_version(
        name: String,
        pid: u32,
        executable: Option<String>,
    ) -> SoftwareInventory {
        let (version, metadata_source) = executable
            .as_deref()
            .map(Path::new)
            .and_then(Self::package_version)
            .map(|(version, source)| (Some(version), Some(source)))
            .unwrap_or((None, None));
        let evidence = if executable.is_none() {
            format!("observed process {}; executable path unavailable", pid)
        } else {
            match metadata_source {
                Some(source) => format!("{} for process {}", source, pid),
                None => format!(
                    "observed process {}; trusted package metadata unavailable",
                    pid
                ),
            }
        };
        SoftwareInventory {
            name,
            version,
            executable,
            evidence,
            observations: 1,
        }
    }

    /// Gets a version from trusted package-manager metadata without executing the
    /// discovered workload executable. This is important because the collector
    /// may run as root while observed processes can belong to unprivileged users.
    fn package_version(executable: &Path) -> Option<(String, &'static str)> {
        let executable = fs::canonicalize(executable).ok()?;
        if !executable.is_file() {
            return None;
        }

        if let Some(version) = Self::dpkg_version(&executable) {
            return Some((version, "dpkg package metadata"));
        }
        Self::rpm_version(&executable).map(|version| (version, "rpm package metadata"))
    }

    fn dpkg_version(executable: &Path) -> Option<String> {
        let executable = executable.to_str()?;
        let dpkg_query = Self::trusted_command_path("dpkg-query")?;
        let ownership = Self::run_bounded_command(
            dpkg_query.clone(),
            &["-S", executable],
            SMALL_PROBE_TIMEOUT,
            SMALL_PROBE_OUTPUT_LIMIT,
        )
        .ok()?;
        if !ownership.status.success() {
            return None;
        }

        let package = String::from_utf8_lossy(&ownership.stdout)
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .map(|(package, _)| package.trim().to_string())
            })?;
        let version = Self::run_bounded_command(
            dpkg_query,
            &["-W", "-f=${Version}", package.as_str()],
            SMALL_PROBE_TIMEOUT,
            SMALL_PROBE_OUTPUT_LIMIT,
        )
        .ok()?;
        Self::metadata_text(&version.stdout, version.status.success())
    }

    fn rpm_version(executable: &Path) -> Option<String> {
        let executable = executable.to_str()?;
        let rpm = Self::trusted_command_path("rpm")?;
        let output = Self::run_bounded_command(
            rpm,
            &["-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}", executable],
            SMALL_PROBE_TIMEOUT,
            SMALL_PROBE_OUTPUT_LIMIT,
        )
        .ok()?;
        Self::metadata_text(&output.stdout, output.status.success())
    }

    fn metadata_text(bytes: &[u8], successful: bool) -> Option<String> {
        if !successful {
            return None;
        }
        let value = String::from_utf8_lossy(bytes)
            .lines()
            .next()?
            .trim()
            .chars()
            .filter(|character| !character.is_control())
            .take(200)
            .collect::<String>();
        (!value.is_empty()).then_some(value)
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
        let scheduled = Self::run_systemctl_with_fallback(
            &["list-timers", "--all", "--no-pager", "--output=json"],
            &[
                "list-timers",
                "--all",
                "--no-pager",
                "--no-legend",
                "--plain",
            ],
            "list-timers",
            Self::parse_systemd_timers_json,
            Self::parse_systemd_timers_text,
        )?;
        let unit_files = Self::run_systemctl_with_fallback(
            &[
                "list-unit-files",
                "--type=timer",
                "--no-pager",
                "--output=json",
            ],
            &[
                "list-unit-files",
                "--type=timer",
                "--no-pager",
                "--no-legend",
            ],
            "list-unit-files",
            Self::parse_systemd_timer_unit_files_json,
            Self::parse_systemd_timer_unit_files_text,
        )?;
        let loaded_units = Self::run_systemctl_with_fallback(
            &[
                "list-units",
                "--all",
                "--type=timer",
                "--no-pager",
                "--output=json",
            ],
            &[
                "list-units",
                "--all",
                "--type=timer",
                "--no-pager",
                "--no-legend",
                "--plain",
            ],
            "list-units",
            Self::parse_systemd_loaded_timer_states_json,
            Self::parse_systemd_loaded_timer_states_text,
        )?;

        Ok(Self::merge_systemd_timer_inventory(
            scheduled,
            unit_files,
            loaded_units,
        ))
    }

    fn run_systemctl_with_fallback<T>(
        json_args: &[&str],
        text_args: &[&str],
        operation: &str,
        parse_json: fn(&[u8]) -> Result<T>,
        parse_text: fn(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let systemctl = Self::trusted_command_path("systemctl")
            .ok_or_else(|| anyhow!("No trusted systemctl utility found"))?;
        let json_output = Self::run_bounded_command(
            systemctl.clone(),
            json_args,
            INVENTORY_PROBE_TIMEOUT,
            SOCKET_PROBE_OUTPUT_LIMIT,
        )
        .with_context(|| format!("Failed to run systemctl {operation}"))?;
        Self::parse_systemctl_output_with_fallback(
            &json_output.stdout,
            json_output.status.success(),
            operation,
            parse_json,
            || {
                let output = Self::run_bounded_command(
                    systemctl,
                    text_args,
                    INVENTORY_PROBE_TIMEOUT,
                    SOCKET_PROBE_OUTPUT_LIMIT,
                )
                .with_context(|| format!("Failed to run systemctl {operation} text fallback"))?;
                if !output.status.success() {
                    return Err(anyhow!(
                        "text fallback exited with status {}",
                        output.status
                    ));
                }
                parse_text(&output.stdout)
            },
        )
    }

    fn parse_systemctl_output_with_fallback<T>(
        json_output: &[u8],
        json_command_succeeded: bool,
        operation: &str,
        parse_json: fn(&[u8]) -> Result<T>,
        text_fallback: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let json_result = if json_command_succeeded {
            parse_json(json_output).context("JSON schema was unsupported")
        } else {
            Err(anyhow!("JSON output mode is unsupported"))
        };
        match json_result {
            Ok(parsed) => Ok(parsed),
            Err(json_error) => text_fallback().with_context(|| {
                format!(
                    "Failed to collect systemctl {operation} in JSON and text modes; JSON error: {json_error}"
                )
            }),
        }
    }

    fn parse_systemd_timers_text(bytes: &[u8]) -> Result<Vec<SystemdTimer>> {
        let output = std::str::from_utf8(bytes).context("systemd timer output was not UTF-8")?;
        let mut timers = BTreeMap::new();
        for (line_number, line) in output.lines().enumerate() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let Some(unit) = fields
                .iter()
                .find(|field| Self::systemd_timer_name(field).is_some())
            else {
                continue;
            };
            let name = Self::systemd_timer_name(unit)
                .ok_or_else(|| anyhow!("invalid timer unit on line {}", line_number + 1))?;
            timers
                .entry((*unit).to_string())
                .or_insert_with(|| SystemdTimer {
                    name: name.to_string(),
                    unit: (*unit).to_string(),
                    enabled: None,
                    active: None,
                });
        }
        Ok(timers.into_values().collect())
    }

    fn parse_systemd_timer_unit_files_text(bytes: &[u8]) -> Result<BTreeMap<String, Option<bool>>> {
        let output =
            std::str::from_utf8(bytes).context("systemd unit-file output was not UTF-8")?;
        let mut unit_files = BTreeMap::new();
        for (line_number, line) in output.lines().enumerate() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.is_empty() {
                continue;
            }
            if Self::systemd_timer_name(fields[0]).is_none() {
                continue;
            }
            let state = fields
                .get(1)
                .ok_or_else(|| anyhow!("unit-file row {} has no state", line_number + 1))?;
            let enabled = match *state {
                "enabled" | "enabled-runtime" => Some(true),
                "disabled" | "masked" | "masked-runtime" => Some(false),
                _ => None,
            };
            unit_files.insert(fields[0].to_string(), enabled);
        }
        Ok(unit_files)
    }

    fn parse_systemd_loaded_timer_states_text(
        bytes: &[u8],
    ) -> Result<BTreeMap<String, Option<bool>>> {
        let output = std::str::from_utf8(bytes).context("systemd unit output was not UTF-8")?;
        let mut loaded = BTreeMap::new();
        for (line_number, line) in output.lines().enumerate() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.is_empty() || Self::systemd_timer_name(fields[0]).is_none() {
                continue;
            }
            let active = fields.get(2).ok_or_else(|| {
                anyhow!("loaded-unit row {} has no active state", line_number + 1)
            })?;
            let active = match *active {
                "active" => Some(true),
                "inactive" => Some(false),
                _ => None,
            };
            loaded.insert(fields[0].to_string(), active);
        }
        Ok(loaded)
    }

    fn parse_systemd_timers_json(bytes: &[u8]) -> Result<Vec<SystemdTimer>> {
        let json = serde_json::from_slice::<serde_json::Value>(bytes)
            .context("systemd returned invalid JSON")?;
        let timers_array = json
            .as_array()
            .or_else(|| json.get("timers").and_then(|t| t.as_array()))
            .ok_or_else(|| anyhow!("systemd JSON did not contain a timer list"))?;

        timers_array
            .iter()
            .enumerate()
            .map(|(index, timer_obj)| {
                if !timer_obj.is_object() {
                    return Err(anyhow!("timer entry {index} was not an object"));
                }
                let unit = timer_obj
                    .get("unit")
                    .and_then(serde_json::Value::as_str)
                    .filter(|unit| !unit.trim().is_empty())
                    .ok_or_else(|| anyhow!("timer entry {index} had no valid unit"))?;
                let name = unit
                    .strip_suffix(".timer")
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| anyhow!("timer entry {index} had an invalid unit name"))?;
                let active = match timer_obj.get("active").and_then(serde_json::Value::as_str) {
                    Some("active") => Some(true),
                    Some("inactive") => Some(false),
                    _ => None,
                };

                Ok(SystemdTimer {
                    name: name.to_string(),
                    unit: unit.to_string(),
                    enabled: None,
                    active,
                })
            })
            .collect()
    }

    fn parse_systemd_timer_unit_files_json(bytes: &[u8]) -> Result<BTreeMap<String, Option<bool>>> {
        let json = serde_json::from_slice::<serde_json::Value>(bytes)
            .context("systemd returned invalid unit-file JSON")?;
        let records = json
            .as_array()
            .or_else(|| json.get("unit_files").and_then(|value| value.as_array()))
            .ok_or_else(|| anyhow!("systemd JSON did not contain a unit-file list"))?;
        let mut unit_files = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            if !record.is_object() {
                return Err(anyhow!("unit-file entry {index} was not an object"));
            }
            let unit = record
                .get("unit_file")
                .and_then(serde_json::Value::as_str)
                .filter(|unit| Self::systemd_timer_name(unit).is_some())
                .ok_or_else(|| anyhow!("unit-file entry {index} had no valid timer unit"))?;
            let enabled = match record.get("state").and_then(serde_json::Value::as_str) {
                Some("enabled" | "enabled-runtime") => Some(true),
                Some("disabled" | "masked" | "masked-runtime") => Some(false),
                _ => None,
            };
            unit_files.insert(unit.to_string(), enabled);
        }
        Ok(unit_files)
    }

    fn parse_systemd_loaded_timer_states_json(
        bytes: &[u8],
    ) -> Result<BTreeMap<String, Option<bool>>> {
        let json = serde_json::from_slice::<serde_json::Value>(bytes)
            .context("systemd returned invalid loaded-unit JSON")?;
        let records = json
            .as_array()
            .or_else(|| json.get("units").and_then(|value| value.as_array()))
            .ok_or_else(|| anyhow!("systemd JSON did not contain a loaded-unit list"))?;
        let mut loaded = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            if !record.is_object() {
                return Err(anyhow!("loaded-unit entry {index} was not an object"));
            }
            let unit = record
                .get("unit")
                .and_then(serde_json::Value::as_str)
                .filter(|unit| Self::systemd_timer_name(unit).is_some())
                .ok_or_else(|| anyhow!("loaded-unit entry {index} had no valid timer unit"))?;
            let active = match record.get("active").and_then(serde_json::Value::as_str) {
                Some("active") => Some(true),
                Some("inactive") => Some(false),
                _ => None,
            };
            loaded.insert(unit.to_string(), active);
        }
        Ok(loaded)
    }

    fn systemd_timer_name(unit: &str) -> Option<&str> {
        unit.strip_suffix(".timer").filter(|name| !name.is_empty())
    }

    fn merge_systemd_timer_inventory(
        scheduled: Vec<SystemdTimer>,
        unit_files: BTreeMap<String, Option<bool>>,
        loaded_units: BTreeMap<String, Option<bool>>,
    ) -> Vec<SystemdTimer> {
        let mut timers = scheduled
            .into_iter()
            .map(|timer| (timer.unit.clone(), timer))
            .collect::<BTreeMap<_, _>>();
        for (unit, enabled) in unit_files {
            let entry = timers.entry(unit.clone()).or_insert_with(|| SystemdTimer {
                name: Self::systemd_timer_name(&unit).unwrap_or(&unit).to_string(),
                unit,
                enabled: None,
                active: None,
            });
            entry.enabled = enabled;
        }
        for (unit, active) in loaded_units {
            let entry = timers.entry(unit.clone()).or_insert_with(|| SystemdTimer {
                name: Self::systemd_timer_name(&unit).unwrap_or(&unit).to_string(),
                unit,
                enabled: None,
                active: None,
            });
            entry.active = active;
        }
        timers.into_values().collect()
    }

    async fn collect_dns_names(
    ) -> Result<(Vec<DnsName>, usize, Vec<ConfigReference>, ConfigScanAudit)> {
        let cache = CONFIG_DNS_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache.lock() {
            if let Some((timestamp, names, unavailable, references, audit)) = guard.as_ref() {
                if timestamp.elapsed() < StdDuration::from_secs(300) {
                    return Ok((
                        names.clone(),
                        *unavailable,
                        references.clone(),
                        audit.clone(),
                    ));
                }
            }
        }

        let (config_refs, config_scan_audit) = ConfigScanner::scan_with_audit()?;
        let timestamp = Utc::now();

        let mut seen = std::collections::HashSet::new();
        let mut hostnames = Vec::new();
        for config_ref in &config_refs {
            let key = config_ref.hostname.to_ascii_lowercase();
            if seen.insert(key) {
                hostnames.push(config_ref.hostname.clone());
            }
        }

        let truncated = hostnames.len().saturating_sub(DNS_LOOKUP_LIMIT);
        hostnames.truncate(DNS_LOOKUP_LIMIT);
        let mut resolved = HashMap::<String, Vec<String>>::new();
        let mut timed_out = false;
        let collection_deadline = Instant::now() + DNS_COLLECTION_TIMEOUT;
        for batch in hostnames.chunks(DNS_LOOKUP_BATCH_SIZE) {
            let now = Instant::now();
            if now >= collection_deadline {
                break;
            }
            let mut tasks = tokio::task::JoinSet::new();
            for hostname in batch {
                let hostname = hostname.clone();
                tasks.spawn_blocking(move || {
                    let addresses = Self::resolve_hostname_addresses(&hostname);
                    (hostname, addresses)
                });
            }

            let mut pending = batch.len();
            let batch_deadline = (now + DNS_LOOKUP_TIMEOUT).min(collection_deadline);
            while pending > 0 {
                let remaining = batch_deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(remaining, tasks.join_next()).await {
                    Ok(Some(Ok((hostname, Ok(addresses))))) => {
                        resolved.insert(hostname, addresses);
                        pending -= 1;
                    }
                    Ok(Some(Ok((hostname, Err(_))))) => {
                        resolved.insert(hostname, Vec::new());
                        pending -= 1;
                    }
                    Ok(Some(Err(_))) => pending -= 1,
                    Ok(None) => break,
                    Err(_) => {
                        timed_out = true;
                        tasks.abort_all();
                        break;
                    }
                }
            }
            if timed_out {
                break;
            }
        }

        let mut names = Vec::with_capacity(hostnames.len());
        for hostname in hostnames {
            names.push(DnsName {
                ip_addresses: resolved.remove(&hostname).unwrap_or_default(),
                hostname,
                timestamp,
            });
        }
        let unavailable = names
            .iter()
            .filter(|name| name.ip_addresses.is_empty())
            .count()
            .saturating_add(truncated);

        if let Ok(mut guard) = cache.lock() {
            *guard = Some((
                Instant::now(),
                names.clone(),
                unavailable,
                config_refs.clone(),
                config_scan_audit.clone(),
            ));
        }
        Ok((names, unavailable, config_refs, config_scan_audit))
    }

    fn resolve_hostname_addresses(hostname: &str) -> io::Result<Vec<String>> {
        use std::net::ToSocketAddrs;
        (hostname, 80)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip().to_string()).collect())
    }

    fn config_scan_probe_status(audit: &ConfigScanAudit) -> Option<ProbeStatus> {
        let recorded_errors = audit.errors.len().saturating_add(audit.errors_truncated);
        if audit.files_skipped == 0 && recorded_errors == 0 {
            return None;
        }

        let unavailable = audit.files_skipped.max(recorded_errors).max(1);
        Some(ProbeStatus::partial(
            format!(
                "configuration scan skipped {} file(s), encountered {} permission denial(s), and recorded {} issue(s)",
                audit.files_skipped,
                audit.permission_denied,
                recorded_errors
            ),
            unavailable,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Collector;
    use crate::models::{ConfigScanAudit, ProbeStatuses};
    use std::collections::HashMap;
    use std::time::Duration;

    #[test]
    fn systemd_timer_inventory_preserves_unknown_state_and_rejects_bad_rows() {
        let timers = Collector::parse_systemd_timers_json(
            br#"[{"unit":"backup.timer","active":"active"},{"unit":"rotate.timer","active":"inactive"},{"unit":"unknown.timer","active":"activating"}]"#,
        )
        .unwrap();
        assert_eq!(timers.len(), 3);
        assert_eq!(timers[0].name, "backup");
        assert_eq!(timers[0].active, Some(true));
        assert_eq!(timers[1].active, Some(false));
        assert_eq!(timers[2].active, None);
        assert!(timers.iter().all(|timer| timer.enabled.is_none()));

        assert!(Collector::parse_systemd_timers_json(br#"[{"active":"active"}]"#).is_err());
        assert!(Collector::parse_systemd_timers_json(br#"[{"unit":5}]"#).is_err());
        assert!(Collector::parse_systemd_timers_json(br#"[{"unit":"backup.service"}]"#).is_err());
        assert!(Collector::parse_systemd_timers_json(b"not json").is_err());
    }

    #[test]
    fn systemd_v259_timer_schedule_install_state_and_runtime_state_are_merged() {
        let scheduled = Collector::parse_systemd_timers_json(include_bytes!(
            "../tests/fixtures/systemd/list-timers-v259.json"
        ))
        .unwrap();
        let unit_files = Collector::parse_systemd_timer_unit_files_json(include_bytes!(
            "../tests/fixtures/systemd/list-unit-files-v259.json"
        ))
        .unwrap();
        let loaded_units = Collector::parse_systemd_loaded_timer_states_json(include_bytes!(
            "../tests/fixtures/systemd/list-units-v259.json"
        ))
        .unwrap();
        let timers = Collector::merge_systemd_timer_inventory(scheduled, unit_files, loaded_units);

        assert_eq!(timers.len(), 7);
        let timer = |name: &str| timers.iter().find(|timer| timer.name == name).unwrap();
        assert_eq!(timer("hourly").enabled, Some(true));
        assert_eq!(timer("hourly").active, Some(true));
        assert_eq!(timer("disabled").enabled, Some(false));
        assert_eq!(timer("disabled").active, Some(false));
        assert_eq!(timer("masked").enabled, Some(false));
        assert_eq!(timer("masked").active, None);
        assert_eq!(timer("static").enabled, None);
        assert_eq!(timer("failed").active, None);
        assert_eq!(timer("transient").enabled, None);
        assert_eq!(timer("transient").active, Some(false));
    }

    #[test]
    fn systemd_v239_text_output_preserves_timer_inventory_and_states() {
        let scheduled = Collector::parse_systemd_timers_text(include_bytes!(
            "../tests/fixtures/systemd/list-timers-v239.txt"
        ))
        .unwrap();
        let unit_files = Collector::parse_systemd_timer_unit_files_text(include_bytes!(
            "../tests/fixtures/systemd/list-unit-files-v239.txt"
        ))
        .unwrap();
        let loaded_units = Collector::parse_systemd_loaded_timer_states_text(include_bytes!(
            "../tests/fixtures/systemd/list-units-v239.txt"
        ))
        .unwrap();
        let timers = Collector::merge_systemd_timer_inventory(scheduled, unit_files, loaded_units);
        let timer = |name: &str| timers.iter().find(|timer| timer.name == name).unwrap();

        assert_eq!(timers.len(), 5);
        assert_eq!(timer("backup").enabled, Some(true));
        assert_eq!(timer("backup").active, Some(true));
        assert_eq!(timer("disabled").enabled, Some(false));
        assert_eq!(timer("cleanup").enabled, Some(false));
        assert_eq!(timer("cleanup").active, Some(false));
        assert_eq!(timer("generated").enabled, None);
        assert_eq!(timer("failed").active, None);
    }

    #[test]
    fn systemd_text_parsers_reject_malformed_timer_rows() {
        assert!(Collector::parse_systemd_timer_unit_files_text(b"broken.timer\n").is_err());
        assert!(
            Collector::parse_systemd_loaded_timer_states_text(b"broken.timer loaded\n").is_err()
        );
        assert!(Collector::parse_systemd_timer_unit_files_text(&[0xff]).is_err());
    }

    #[test]
    fn systemd_fallback_runs_on_schema_mismatch_but_not_valid_json() {
        let mut fallback_called = false;
        let from_text = Collector::parse_systemctl_output_with_fallback(
            br#"{"different_shape":[]}"#,
            true,
            "list-unit-files",
            Collector::parse_systemd_timer_unit_files_json,
            || {
                fallback_called = true;
                Collector::parse_systemd_timer_unit_files_text(include_bytes!(
                    "../tests/fixtures/systemd/list-unit-files-v239.txt"
                ))
            },
        )
        .unwrap();
        assert!(fallback_called);
        assert_eq!(from_text.get("backup.timer"), Some(&Some(true)));

        let mut fallback_called = false;
        let from_json = Collector::parse_systemctl_output_with_fallback(
            include_bytes!("../tests/fixtures/systemd/list-unit-files-v259.json"),
            true,
            "list-unit-files",
            Collector::parse_systemd_timer_unit_files_json,
            || {
                fallback_called = true;
                unreachable!("valid JSON must not run the text fallback")
            },
        )
        .unwrap();
        assert!(!fallback_called);
        assert_eq!(from_json.get("hourly.timer"), Some(&Some(true)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_loopback_tcp_connection_is_visible_to_socket_collector() {
        use std::net::{TcpListener, TcpStream};
        use std::sync::mpsc;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let accept_thread = std::thread::spawn(move || {
            let (connection, _) = listener.accept().unwrap();
            accepted_tx.send(connection).unwrap();
        });
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let server = accepted_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("loopback accept should complete");

        let pid = std::process::id();
        let process = HashMap::from([(
            pid,
            ("screamless-test".to_string(), 0, "test-user".to_string()),
        )]);
        let (connections, _, _) = Collector::collect_network_connections(&process).unwrap();
        assert!(
            connections.iter().any(|connection| {
                connection.protocol == "tcp"
                    && connection.state == "ESTABLISHED"
                    && (connection.local_port == port || connection.remote_port == port)
            }),
            "active loopback connection on port {port} was missing from socket observation"
        );
        assert!(
            connections.iter().any(|connection| {
                connection.pid == pid
                    && connection.process_name == "screamless-test"
                    && (connection.local_port == port || connection.remote_port == port)
            }),
            "socket collector did not attribute the loopback connection to PID {pid}"
        );

        drop(client);
        drop(server);
        accept_thread.join().unwrap();
    }

    #[test]
    fn systemd_state_parsers_reject_wrong_unit_types_and_bad_json() {
        assert!(Collector::parse_systemd_timer_unit_files_json(
            br#"[{"unit_file":"backup.service","state":"enabled"}]"#
        )
        .is_err());
        assert!(Collector::parse_systemd_loaded_timer_states_json(
            br#"[{"unit":"backup.service","active":"active"}]"#
        )
        .is_err());
        assert!(Collector::parse_systemd_timer_unit_files_json(b"not json").is_err());
        assert!(Collector::parse_systemd_loaded_timer_states_json(b"not json").is_err());
    }

    #[test]
    fn incomplete_slow_inventory_retries_before_hourly_refresh() {
        assert_eq!(
            Collector::slow_refresh_interval(&ProbeStatuses::default()),
            Duration::from_secs(60 * 60)
        );

        let statuses = ProbeStatuses {
            systemd: crate::models::ProbeStatus::failed("systemctl unavailable"),
            ..ProbeStatuses::default()
        };
        assert_eq!(
            Collector::slow_refresh_interval(&statuses),
            Duration::from_secs(5 * 60)
        );

        let statuses = ProbeStatuses {
            host_identity: crate::models::ProbeStatus::failed("address tools unavailable"),
            ..ProbeStatuses::default()
        };
        assert_eq!(
            Collector::slow_refresh_interval(&statuses),
            Duration::from_secs(5 * 60)
        );

        let statuses = ProbeStatuses {
            process_attribution: crate::models::ProbeStatus::partial("limited", 1),
            ..ProbeStatuses::default()
        };
        assert_eq!(
            Collector::slow_refresh_interval(&statuses),
            Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn older_probe_status_records_treat_host_identity_as_unknown() {
        let mut value = serde_json::to_value(ProbeStatuses::default()).unwrap();
        value.as_object_mut().unwrap().remove("host_identity");
        let decoded: ProbeStatuses = serde_json::from_value(value).unwrap();
        assert!(!decoded.host_identity.is_complete());
        assert!(decoded
            .host_identity
            .details
            .as_deref()
            .unwrap()
            .contains("unavailable"));
    }

    #[test]
    fn parses_interface_addresses_and_rejects_malformed_values() {
        let addresses = Collector::parse_interface_addresses_json(
            r#"[
                {"ifname":"eth0","addr_info":[
                    {"family":"inet","local":"192.0.2.10"},
                    {"family":"inet6","local":"2001:db8::10"},
                    {"family":"inet","local":"not-an-ip"}
                ]}
            ]"#,
        )
        .unwrap();
        assert_eq!(addresses, vec!["192.0.2.10", "2001:db8::10"]);
        assert!(Collector::parse_interface_addresses_json("not json").is_none());
        assert!(Collector::parse_interface_addresses_json("[]").is_none());
    }

    #[test]
    fn hostname_address_fallback_reports_empty_and_failed_probes() {
        let (addresses, status) = Collector::parse_hostname_interface_addresses(Some(
            "192.0.2.11 2001:db8::11 malformed",
        ));
        assert_eq!(addresses, vec!["192.0.2.11", "2001:db8::11"]);
        assert!(status.is_complete());

        let (addresses, status) = Collector::parse_hostname_interface_addresses(Some("\n"));
        assert!(addresses.is_empty());
        assert_eq!(status.state, crate::models::ProbeState::Partial);

        let (addresses, status) = Collector::parse_hostname_interface_addresses(None);
        assert!(addresses.is_empty());
        assert_eq!(status.state, crate::models::ProbeState::Failed);
    }

    #[test]
    fn fast_probe_statuses_reset_without_discarding_slow_probe_gaps() {
        let mut statuses = ProbeStatuses {
            network_sockets: crate::models::ProbeStatus::failed("ss failed"),
            process_attribution: crate::models::ProbeStatus::partial("restricted", 2),
            dns: crate::models::ProbeStatus::partial("DNS timeout", 1),
            ..ProbeStatuses::default()
        };

        Collector::reset_fast_probe_statuses(&mut statuses);

        assert!(statuses.network_sockets.is_complete());
        assert!(statuses.process_attribution.is_complete());
        assert_eq!(statuses.dns.state, crate::models::ProbeState::Partial);
    }

    #[test]
    fn process_inventory_counts_permission_failures_but_not_exit_races() {
        assert!(!Collector::process_error_requires_partial(
            &procfs::ProcError::NotFound(None)
        ));
        assert!(Collector::process_error_requires_partial(
            &procfs::ProcError::PermissionDenied(None)
        ));
        assert!(Collector::process_error_requires_partial(
            &procfs::ProcError::Incomplete(None)
        ));
    }

    #[test]
    fn process_attribution_gap_counts_inventory_and_socket_failures() {
        let status = Collector::process_attribution_status(2, 3, None).unwrap();
        assert_eq!(status.unavailable, 5);
        assert!(status.details.unwrap().contains("2 entry/entries"));
        assert!(Collector::process_attribution_status(0, 0, None).is_none());
    }

    #[test]
    fn software_inventory_recognizes_common_database_server_processes() {
        for process in [
            "postgres",
            "mysqld",
            "mariadbd",
            "mongod",
            "mongos",
            "redis-server",
            "memcached",
            "sqlservr",
        ] {
            assert!(Collector::is_known_software(process), "{process}");
        }
        assert_eq!(Collector::software_name("postgres"), "postgresql");
        assert_eq!(Collector::software_name("mariadbd"), "mariadb");
        assert_eq!(Collector::software_name("mongod"), "mongodb");
        assert_eq!(Collector::software_name("redis-server"), "redis");
    }

    #[test]
    fn host_utility_resolution_accepts_only_root_owned_system_binaries() {
        let hostname = Collector::trusted_command_path("hostname")
            .expect("hostname should be installed on Linux CI");
        assert!(hostname.is_absolute());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(hostname).unwrap();
            assert_eq!(metadata.uid(), 0);
            assert_eq!(metadata.mode() & 0o022, 0);
        }
        assert!(Collector::trusted_command_path("../hostname").is_none());
        assert!(Collector::trusted_command_path("hostname;id").is_none());
    }

    #[test]
    fn software_versions_come_from_trusted_package_metadata() {
        let executable = ["dpkg-query", "rpm"]
            .into_iter()
            .find_map(Collector::trusted_command_path)
            .expect("a supported package manager should be installed on Linux CI");
        let (version, source) = Collector::package_version(&executable)
            .expect("the package manager executable should have package metadata");

        assert!(!version.trim().is_empty());
        assert!(matches!(
            source,
            "dpkg package metadata" | "rpm package metadata"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn software_inventory_never_executes_the_observed_executable() {
        use std::os::unix::fs::PermissionsExt;

        if std::env::var_os("SCREAMLESS_REQUIRE_ROOT_TEST").is_some() {
            // The dedicated CI invocation runs this regression under root to
            // exercise the exact privilege boundary the collector protects.
            assert_eq!(unsafe { libc::geteuid() }, 0);
        }

        let test_dir = std::env::temp_dir().join(format!(
            "screamless-untrusted-software-probe-{}",
            std::process::id()
        ));
        std::fs::create_dir(&test_dir).unwrap();
        let executable = test_dir.join("nginx");
        let marker = test_dir.join("executed");
        let marker_literal = marker.to_string_lossy().replace('\'', "'\\''");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf executed > '{}'\n", marker_literal),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();

        let inventory = Collector::collect_software_version(
            "nginx".to_string(),
            123,
            Some(executable.display().to_string()),
        );

        assert_eq!(inventory.version, None);
        assert!(
            !marker.exists(),
            "inventory collection executed an observed workload binary"
        );
        std::fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn software_inventory_keeps_process_when_executable_path_is_unavailable() {
        let inventory = Collector::collect_software_version("postgresql".to_string(), 42, None);

        assert_eq!(inventory.name, "postgresql");
        assert_eq!(inventory.version, None);
        assert_eq!(inventory.executable, None);
        assert!(inventory.evidence.contains("executable path unavailable"));
    }

    #[test]
    fn bounded_utility_runner_rejects_deadlines_and_excess_output() {
        let sleep = Collector::trusted_command_path("sleep").unwrap();
        let timeout =
            Collector::run_bounded_command(sleep, &["2"], Duration::from_millis(30), 1024)
                .unwrap_err();
        assert_eq!(timeout.kind(), std::io::ErrorKind::TimedOut);

        let printf = Collector::trusted_command_path("printf").unwrap();
        let oversized =
            Collector::run_bounded_command(printf, &["12345"], Duration::from_secs(1), 4)
                .unwrap_err();
        assert_eq!(oversized.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_utility_runner_terminates_descendants_holding_output_pipes() {
        let shell = Collector::trusted_command_path("sh").unwrap();
        let started = std::time::Instant::now();
        let output = Collector::run_bounded_command(
            shell,
            &["-c", "sleep 30 & exit 0"],
            Duration::from_secs(2),
            1024,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "command runner waited for a descendant to close inherited pipes"
        );
    }

    #[test]
    fn resolves_ipv6_literals_without_adding_ambiguous_port_syntax() {
        assert_eq!(
            Collector::resolve_hostname_addresses("::1").unwrap(),
            vec!["::1".to_string()]
        );
    }

    #[test]
    fn skipped_config_files_make_config_probe_partial() {
        let audit = ConfigScanAudit {
            files_discovered: 4,
            files_parsed: 3,
            files_skipped: 1,
            permission_denied: 1,
            errors: vec!["/etc/example.conf: permission denied".to_string()],
            ..ConfigScanAudit::default()
        };
        let status = Collector::config_scan_probe_status(&audit).unwrap();
        assert!(!status.is_complete());
        assert_eq!(status.unavailable, 1);
        assert!(status.details.unwrap().contains("permission denial"));
    }

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
        assert!(Collector::is_socket_record(&parts));
        assert_eq!(Collector::find_endpoints(&parts).len(), 2);
    }

    #[test]
    fn parses_complete_iproute2_ss_fixture() {
        let pid_map = HashMap::from([(1234, ("worker".to_string(), 1000, "worker".to_string()))]);
        let (connections, unavailable, malformed) = Collector::parse_network_connections_output(
            include_str!("../tests/fixtures/network/ss-iproute2.txt"),
            &pid_map,
        );

        assert_eq!(connections.len(), 2);
        assert_eq!(unavailable, 0);
        assert_eq!(malformed, 0);
        assert_eq!(connections[0].local_addr, "192.0.2.10");
        assert_eq!(connections[0].remote_addr, "192.0.2.20");
        assert_eq!(connections[0].remote_port, 443);
        assert_eq!(connections[0].process_name, "worker");
        assert_eq!(connections[1].local_addr, "2001:db8::10");
        assert_eq!(connections[1].remote_addr, "2001:db8::20");
        assert_eq!(connections[1].protocol, "tcp");
    }

    #[test]
    fn parses_complete_netstat_fixture() {
        let pid_map = HashMap::from([(1234, ("worker".to_string(), 1000, "worker".to_string()))]);
        let (connections, unavailable, malformed) = Collector::parse_network_connections_output(
            include_str!("../tests/fixtures/network/netstat-ubuntu.txt"),
            &pid_map,
        );

        assert_eq!(connections.len(), 2);
        assert_eq!(unavailable, 0);
        assert_eq!(malformed, 0);
        assert_eq!(connections[0].remote_addr, "127.0.0.1");
        assert_eq!(connections[0].remote_port, 40689);
        assert_eq!(connections[0].process_name, "worker");
        assert_eq!(connections[1].local_addr, "2001:db8::10");
        assert_eq!(connections[1].remote_addr, "2001:db8::20");
    }

    #[test]
    fn recognizes_transitional_tcp_states_and_incomplete_rows() {
        let transitional = "SYN-SENT 0 1 192.0.2.10:49152 192.0.2.20:443";
        let parts: Vec<&str> = transitional.split_whitespace().collect();
        assert!(Collector::is_socket_record(&parts));
        assert!(Collector::is_connection_line(&parts));
        assert!(!Collector::is_malformed_connection_row(&parts));

        let malformed = "SYN-SENT 0 1 local-address peer-address";
        let parts: Vec<&str> = malformed.split_whitespace().collect();
        assert!(Collector::is_malformed_connection_row(&parts));

        let unconnected_udp = "UNCONN 0 0 0.0.0.0:5353 *:*";
        let parts: Vec<&str> = unconnected_udp.split_whitespace().collect();
        assert!(!Collector::is_malformed_connection_row(&parts));
    }

    #[test]
    fn recognizes_netstat_underscore_tcp_states() {
        let fixture = "tcp 0 0 192.0.2.10:49152 192.0.2.20:443 SYN_SENT 1234/node";
        let parts: Vec<&str> = fixture.split_whitespace().collect();

        assert!(Collector::is_socket_record(&parts));
        assert!(Collector::is_connection_line(&parts));
        assert_eq!(Collector::socket_state(&parts), "SYN-SENT");
        assert_eq!(Collector::find_endpoints(&parts).len(), 2);

        for (state, expected) in [
            ("FIN_WAIT1", "FIN-WAIT-1"),
            ("FIN_WAIT2", "FIN-WAIT-2"),
            ("TIME_WAIT", "TIME-WAIT"),
            ("CLOSE_WAIT", "CLOSE-WAIT"),
            ("LAST_ACK", "LAST-ACK"),
            ("SYN_RECV", "SYN-RECV"),
        ] {
            let parts = ["tcp", "0", "0", "192.0.2.10:1", "192.0.2.20:2", state];
            assert!(Collector::is_connection_line(&parts), "state {state}");
            assert_eq!(Collector::socket_state(&parts), expected);
        }
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
