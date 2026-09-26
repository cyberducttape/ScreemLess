use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::collector::{CollectionState, Collector};
use crate::db::Database;
use crate::report::Reporter;

const SNAPSHOT_RETENTION_DAYS: i64 = 30;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser)]
#[command(name = "screamless")]
#[command(about = "Automatic Linux dependency archaeology", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,

    /// Database file path
    #[arg(global = true, long, default_value = "./screamless.db")]
    pub db: PathBuf,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start observing a server
    Observe {
        /// Observation duration (e.g. "1h", "30m", "24h", "7d"). Default: 7d
        #[arg(short, long)]
        duration: Option<String>,

        /// Interval between snapshots (default: 1m)
        #[arg(short, long)]
        interval: Option<String>,
    },

    /// Generate a report from collected observations
    Report {
        /// Hostname to report on
        #[arg(long)]
        hostname: Option<String>,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Check decommission readiness
    DecommissionCheck {
        /// Hostname to check
        #[arg(long)]
        hostname: Option<String>,
    },

    /// Generate interactive HTML dashboard
    Dashboard {
        /// Hostname to analyze
        #[arg(long)]
        hostname: Option<String>,

        /// Output file path (default: ./screamless-dashboard.html)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Map infrastructure dependencies across multiple servers
    Infrastructure {
        /// Comma-separated list of servers to analyze
        #[arg(short, long)]
        servers: String,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Pre-flight safety check before deployment
    Preflight {
        /// Hostname to check
        #[arg(short, long)]
        server: String,

        /// Operation to validate (restart, update, shutdown)
        #[arg(short, long)]
        operation: String,

        /// Emit a stable JSON result for automation
        #[arg(long)]
        json: bool,

        /// Explicitly acknowledge observed dependent-system impact
        #[arg(long)]
        acknowledge_impact: bool,
    },

    /// Take a single snapshot
    Snapshot,
}

pub async fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Observe { duration, interval } => observe(&args.db, duration, interval).await,
        Command::Report { hostname, format } => report(&args.db, hostname, format),
        Command::DecommissionCheck { hostname } => decommission_check(&args.db, hostname),
        Command::Dashboard { hostname, output } => dashboard(&args.db, hostname, output),
        Command::Infrastructure { servers, format } => infrastructure(&args.db, servers, format),
        Command::Preflight {
            server,
            operation,
            json,
            acknowledge_impact,
        } => preflight(&args.db, server, operation, json, acknowledge_impact),
        Command::Snapshot => snapshot(&args.db).await,
    }
}

async fn snapshot(db_path: &std::path::Path) -> Result<()> {
    println!("Collecting system snapshot...");

    let snapshot = Collector::collect_snapshot().await?;
    let hostname = snapshot.hostname.clone();

    println!("  Hostname: {}", hostname);
    println!(
        "  Listening services: {}",
        snapshot.listening_services.len()
    );
    println!(
        "  Socket observations: {}",
        snapshot.network_connections.len()
    );
    println!("  Processes: {}", snapshot.processes.len());
    println!("  Cron jobs: {}", snapshot.cron_jobs.len());
    println!("  Systemd timers: {}", snapshot.systemd_timers.len());

    let mut db = Database::new(db_path)?;
    db.store_snapshot(&snapshot)?;

    println!("\nSnapshot stored in {}", db_path.display());

    Ok(())
}

async fn observe(
    db_path: &std::path::Path,
    duration: Option<String>,
    interval: Option<String>,
) -> Result<()> {
    let duration = parse_duration(&duration.unwrap_or_else(|| "7d".to_string()))?;
    let interval = parse_duration(&interval.unwrap_or_else(|| "1m".to_string()))?;

    println!(
        "Observing for {} (collecting every {})",
        format_duration(duration),
        format_duration(interval)
    );
    println!("Press Ctrl+C to stop early\n");

    let mut db = Database::new(db_path)?;
    let mut collection_state = CollectionState::default();
    let start = std::time::Instant::now();
    let run_id = format!("{}-{}", Utc::now().timestamp_millis(), std::process::id());
    info!(
        run_id = %run_id,
        event = "observation_started",
        duration_seconds = duration.as_secs(),
        interval_seconds = interval.as_secs(),
        "starting observation run"
    );

    loop {
        if start.elapsed() >= duration {
            break;
        }
        let collection_started = Instant::now();
        match Collector::collect_snapshot_with_state(&mut collection_state).await {
            Ok(mut snapshot) => {
                snapshot.sampling_interval_seconds = Some(interval.as_secs().max(1));
                db.store_snapshot(&snapshot)?;
                db.prune_snapshots_before(
                    (chrono::Utc::now() - chrono::Duration::days(SNAPSHOT_RETENTION_DAYS))
                        .timestamp_millis(),
                )?;

                println!(
                    "[{}] Snapshot collected: {} services, {} socket observations",
                    chrono::Local::now().format("%H:%M:%S"),
                    snapshot.listening_services.len(),
                    snapshot.network_connections.len()
                );
                info!(
                    run_id = %run_id,
                    snapshot_id = %format!("{}-{}", snapshot.hostname, snapshot.timestamp.timestamp_millis()),
                    collection_ms = collection_started.elapsed().as_millis() as u64,
                    socket_observations = snapshot.network_connections.len(),
                    process_count = snapshot.processes.len(),
                    event = "snapshot_collected",
                    "observation snapshot collected"
                );
            }
            Err(e) => {
                warn!(
                    run_id = %run_id,
                    collection_ms = collection_started.elapsed().as_millis() as u64,
                    error = %e,
                    event = "snapshot_failed",
                    "observation snapshot failed"
                );
                eprintln!("Error collecting snapshot: {}", e)
            }
        }

        if start.elapsed() >= duration {
            break;
        }

        let collection_duration = collection_started.elapsed();
        let remaining_run_duration = duration.saturating_sub(start.elapsed());
        let wait = sampling_wait(interval, collection_duration, remaining_run_duration);
        if collection_duration >= interval {
            warn!(
                run_id = %run_id,
                collection_ms = collection_duration.as_millis() as u64,
                interval_ms = interval.as_millis() as u64,
                event = "sampling_interval_overrun",
                "collection exceeded the configured sampling interval"
            );
        }
        if !wait.is_zero() {
            time::sleep(wait).await;
        }
    }

    println!("\nObservation complete. Run 'screamless report' to analyze.");
    info!(run_id = %run_id, event = "observation_completed", "observation run completed");
    Ok(())
}

fn report(db_path: &std::path::Path, hostname: Option<String>, format: OutputFormat) -> Result<()> {
    let db = Database::new(db_path)?;
    let reporter = Reporter::new(&db);

    match format {
        OutputFormat::Json => reporter.report_json(&hostname)?,
        OutputFormat::Text => reporter.report_text(&hostname)?,
    }

    Ok(())
}

fn decommission_check(db_path: &std::path::Path, hostname: Option<String>) -> Result<()> {
    let db = Database::new(db_path)?;
    let reporter = Reporter::new(&db);
    let exit_code = reporter.decommission_check(&hostname)?;

    if exit_code == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::new(CliExit {
            code: exit_code,
            message: format!("Decommission evidence status: exit code {}", exit_code),
        }))
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    let re = regex::Regex::new(r"^(\d+)([smhd])$")?;

    let caps = re.captures(s).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid duration format: {}. Use format like '1h', '30m', '1d'",
            s
        )
    })?;

    let value: u64 = caps[1].parse()?;
    let unit = &caps[2];

    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => unreachable!(),
    };
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("Duration is too large: {}", s))?;
    if seconds == 0 {
        return Err(anyhow::anyhow!("Duration must be greater than zero"));
    }

    Ok(Duration::from_secs(seconds))
}

fn sampling_wait(
    interval: Duration,
    collection_duration: Duration,
    remaining_run_duration: Duration,
) -> Duration {
    interval
        .saturating_sub(collection_duration)
        .min(remaining_run_duration)
}

fn operation_impact_warnings(operation: &str, dependent_systems: usize) -> Vec<String> {
    if dependent_systems == 0 {
        return Vec::new();
    }
    match operation {
        "restart" | "reboot" => vec![format!(
            "{} systems depend on this server and may be interrupted by the {}",
            dependent_systems, operation
        )],
        "update" => vec![format!(
            "{} dependent systems may be interrupted if the update restarts services",
            dependent_systems
        )],
        "shutdown" => vec![format!(
            "CRITICAL: {} systems depend on this server; shutdown would interrupt them",
            dependent_systems
        )],
        _ => Vec::new(),
    }
}

fn impact_requires_acknowledgement(operation: &str, dependent_systems: usize) -> bool {
    dependent_systems > 0 && matches!(operation, "restart" | "reboot" | "update" | "shutdown")
}

fn dashboard(
    db_path: &std::path::Path,
    hostname: Option<String>,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    use crate::analysis::Analyzer;

    let db = Database::new(db_path)?;
    let analyzer = Analyzer::new(&db);

    let hostname = if let Some(h) = hostname {
        h
    } else {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string())
    };

    let analysis = analyzer.analyze(&hostname, 168)?;

    let output_path =
        output.unwrap_or_else(|| std::path::PathBuf::from("screamless-dashboard.html"));

    let html = crate::dashboard::render_dashboard(&hostname, &analysis)?;
    write_private_file(&output_path, html.as_bytes())?;

    println!("Dashboard generated: {}", output_path.display());
    println!("Open in browser to view interactive dependency analysis.");

    Ok(())
}

fn write_private_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Output path has no filename: {}", path.display()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{}.{}.tmp", name, std::process::id()));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .map_err(anyhow::Error::from)
            .with_context(|| {
                format!("Unable to create temporary output {}", temporary.display())
            })?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
            .with_context(|| format!("Unable to replace output {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn infrastructure(db_path: &std::path::Path, servers: String, format: OutputFormat) -> Result<()> {
    use crate::analysis::Analyzer;
    use crate::infrastructure::InfrastructureMapper;
    use std::collections::HashMap;

    let db = Database::new(db_path)?;
    let analyzer = Analyzer::new(&db);

    let mut requested_hosts = std::collections::HashSet::new();
    let server_list: Vec<String> = servers
        .split(',')
        .filter_map(|server| {
            let server = server.trim();
            if server.is_empty() {
                return None;
            }
            let normalized = server.trim_end_matches('.').to_ascii_lowercase();
            requested_hosts
                .insert(normalized)
                .then(|| server.to_string())
        })
        .collect();
    let mut server_analyses = HashMap::new();
    let json_output = matches!(format, OutputFormat::Json);

    if !json_output {
        println!("\nAnalyzing {} servers...\n", server_list.len());
    }

    let analyses = analyzer.analyze_many(&server_list, 168)?;
    for server in &server_list {
        if let Some(analysis) = analyses.get(server) {
            if !json_output {
                println!("  ✓ {}", server);
            }
            server_analyses.insert(
                server.clone(),
                (analysis.clone(), analysis.inbound_dependencies.clone()),
            );
        }
    }

    let chains = InfrastructureMapper::build_full_dependency_graph(&server_analyses);
    let high_fan_in = InfrastructureMapper::find_high_fan_in_services(&chains);
    let clusters = InfrastructureMapper::find_dependency_clusters(&chains);

    if json_output {
        let hosts = server_list
            .iter()
            .filter_map(|hostname| {
                server_analyses.get(hostname).map(|(analysis, _)| {
                    serde_json::json!({
                        "hostname": hostname,
                        "analysis": analysis,
                    })
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": "3.0",
                "generated_at": Utc::now().to_rfc3339(),
                "collector_version": env!("CARGO_PKG_VERSION"),
                "observation_window": {
                    "requested_hours": 168,
                    "hosts_requested": server_list,
                },
                "hosts": hosts,
                "servers_analyzed": server_analyses.len(),
                "dependency_chains": chains,
                "high_fan_in_candidates": high_fan_in,
                "high_fan_in_services": high_fan_in,
                "clusters": clusters,
                "errors": [],
            }))?
        );
        return Ok(());
    }

    println!("\n╭──────────────────────────────────────────╮");
    println!("│   INFRASTRUCTURE DEPENDENCY MAP          │");
    println!("╰──────────────────────────────────────────╯\n");

    println!("Servers analyzed: {}\n", server_analyses.len());

    if !high_fan_in.is_empty() {
        println!("⚠️  HIGH-FAN-IN DEPENDENCY CANDIDATES (redundancy not verified):");
        for server in high_fan_in {
            println!("  - {} (multiple observed dependents)", server);
        }
        println!();
    }

    if !clusters.is_empty() {
        println!("DEPENDENCY CLUSTERS:");
        for (i, cluster) in clusters.iter().enumerate() {
            println!("  Cluster {}: {} servers", i + 1, cluster.len());
            for server in cluster.iter().take(5) {
                println!("    - {}", server);
            }
            if cluster.len() > 5 {
                println!("    - ... and {} more", cluster.len() - 5);
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct CliExit {
    pub code: u8,
    pub message: String,
}

impl std::fmt::Display for CliExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliExit {}

pub fn error_exit_code(error: &anyhow::Error) -> u8 {
    error
        .downcast_ref::<CliExit>()
        .map(|exit| exit.code)
        .unwrap_or(1)
}

#[derive(Serialize)]
struct PreflightResult {
    schema_version: String,
    server: String,
    operation: String,
    status: String,
    safe: bool,
    exit_code: u8,
    warnings: Vec<String>,
    outbound_dependencies: usize,
    inbound_dependencies: usize,
    impact_acknowledged: bool,
    probe_statuses: crate::models::ProbeStatuses,
}

fn preflight(
    db_path: &std::path::Path,
    server: String,
    operation: String,
    json: bool,
    acknowledge_impact: bool,
) -> Result<()> {
    use crate::analysis::Analyzer;

    if !matches!(
        operation.as_str(),
        "restart" | "reboot" | "update" | "shutdown"
    ) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "server": server,
                    "operation": operation,
                    "status": "invalid_invocation",
                    "safe": false,
                    "exit_code": 3,
                    "warnings": ["Use restart, reboot, update, or shutdown"]
                }))?
            );
        }
        return Err(anyhow::Error::new(CliExit {
            code: 3,
            message: format!(
                "Unknown operation '{}'. Use restart, reboot, update, or shutdown",
                operation
            ),
        }));
    }

    let db = Database::new(db_path)?;
    let analyzer = Analyzer::new(&db);
    let analysis = analyzer.analyze(&server, 168)?;

    let mut safe = true;
    let mut warnings = Vec::new();
    let insufficient_evidence = !Reporter::has_sufficient_evidence(
        analysis.total_snapshots,
        analysis.probe_statuses.all_complete(),
        &analysis.coverage.evidence_quality,
        analysis.coverage.coverage_percent,
    );

    if analysis.total_snapshots == 0 {
        warnings.push("No observations are available for this server".to_string());
        safe = false;
    } else if !analysis.probe_statuses.all_complete() {
        warnings.push(
            "Required observation probes are incomplete; safety cannot be established".to_string(),
        );
        safe = false;
    } else if insufficient_evidence {
        warnings.push(
            "Observation coverage, evidence quality, or endpoint attribution is insufficient to establish safety".to_string(),
        );
        warnings.extend(analysis.coverage.remaining_unknowns.iter().take(3).cloned());
        safe = false;
    }

    let impact_warnings =
        operation_impact_warnings(&operation, analysis.inbound_dependencies.len());
    let impact_acknowledged = acknowledge_impact && !impact_warnings.is_empty();
    if !impact_warnings.is_empty() {
        warnings.extend(impact_warnings);
        if impact_acknowledged {
            warnings.push(
                "The caller acknowledged the observed impact; coordinate affected systems and follow the approved maintenance plan.".to_string(),
            );
        } else if impact_requires_acknowledgement(&operation, analysis.inbound_dependencies.len()) {
            safe = false;
            warnings.push(
                "Pass --acknowledge-impact only after confirming the affected systems and approved maintenance plan.".to_string(),
            );
        }
    }

    let exit_code = if insufficient_evidence {
        4
    } else if safe {
        0
    } else {
        2
    };
    let status = match exit_code {
        0 => "safe",
        2 => "blocked",
        4 => "insufficient_evidence",
        _ => unreachable!(),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&PreflightResult {
                schema_version: "1.0".to_string(),
                server,
                operation,
                status: status.to_string(),
                safe,
                exit_code,
                warnings: warnings.clone(),
                outbound_dependencies: analysis.dependencies.len(),
                inbound_dependencies: analysis.inbound_dependencies.len(),
                impact_acknowledged,
                probe_statuses: analysis.probe_statuses.clone(),
            })?
        );
    } else {
        println!("\n╭──────────────────────────────────────────╮");
        println!("│   PREFLIGHT SAFETY CHECK                 │");
        println!("╰──────────────────────────────────────────╯\n");
        println!("Server: {}", server);
        println!("Operation: {}\n", operation);

        if safe {
            println!("✅ SAFE TO PROCEED\n");
            println!("No blocking issues detected for this operation.");
        } else {
            println!("⚠️  PROCEED WITH CAUTION\n");
            println!("Issues identified:");
            for warning in &warnings {
                println!("  - {}", warning);
            }
            println!();
        }

        if !warnings.is_empty() && !safe {
            println!("Recommendations:");
            println!("  1. Notify dependent systems");
            println!("  2. Plan maintenance window");
            println!("  3. Have rollback plan");
        }
    }

    if exit_code == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::new(CliExit {
            code: exit_code,
            message: format!("Preflight status: {}", status),
        }))
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        impact_requires_acknowledgement, operation_impact_warnings, parse_duration, sampling_wait,
        Args,
    };
    use clap::Parser;
    use std::time::Duration;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172800));
    }

    #[test]
    fn rejects_zero_and_overflowing_durations() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("999999999999999999999999d").is_err());
    }

    #[test]
    fn report_format_is_a_validated_enum() {
        assert!(Args::try_parse_from(["screamless", "report", "--format", "json"]).is_ok());
        assert!(Args::try_parse_from(["screamless", "report", "--format", "yaml"]).is_err());
    }

    #[test]
    fn sampling_wait_uses_start_to_start_cadence_and_respects_run_end() {
        assert_eq!(
            sampling_wait(
                Duration::from_secs(60),
                Duration::from_secs(5),
                Duration::from_secs(120)
            ),
            Duration::from_secs(55)
        );
        assert_eq!(
            sampling_wait(
                Duration::from_secs(60),
                Duration::from_secs(65),
                Duration::from_secs(120)
            ),
            Duration::ZERO
        );
        assert_eq!(
            sampling_wait(
                Duration::from_secs(60),
                Duration::from_secs(5),
                Duration::from_secs(10)
            ),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn maintenance_impact_uses_inbound_dependents_not_outbound_consumption() {
        assert!(operation_impact_warnings("update", 0).is_empty());
        assert!(operation_impact_warnings("shutdown", 0).is_empty());
        assert!(operation_impact_warnings("update", 2)[0].contains("2 dependent systems"));
        assert!(operation_impact_warnings("shutdown", 2)[0].contains("shutdown would interrupt"));
        assert!(!impact_requires_acknowledgement("restart", 0));
        assert!(impact_requires_acknowledgement("restart", 2));
        assert!(impact_requires_acknowledgement("shutdown", 2));
        assert!(!impact_requires_acknowledgement("snapshot", 2));
    }

    #[test]
    fn preflight_impact_acknowledgement_is_explicit_in_cli() {
        assert!(Args::try_parse_from([
            "screamless",
            "preflight",
            "--server",
            "db01",
            "--operation",
            "restart",
            "--acknowledge-impact"
        ])
        .is_ok());
    }
}
