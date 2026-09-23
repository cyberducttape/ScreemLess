use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::PathBuf;
use tokio::time::{self, Duration};

use crate::collector::Collector;
use crate::db::Database;
use crate::report::Reporter;
use crate::analysis::Analyzer;

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
        format: String,
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
        format: String,
    },

    /// Pre-flight safety check before deployment
    Preflight {
        /// Hostname to check
        #[arg(short, long)]
        server: String,

        /// Operation to validate (restart, update, shutdown)
        #[arg(short, long)]
        operation: String,
    },

    /// Take a single snapshot
    Snapshot,
}

pub async fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Observe { duration, interval } => {
            observe(&args.db, duration, interval).await
        }
        Command::Report { hostname, format } => {
            report(&args.db, hostname, format)
        }
        Command::DecommissionCheck { hostname } => {
            decommission_check(&args.db, hostname)
        }
        Command::Dashboard { hostname, output } => {
            dashboard(&args.db, hostname, output)
        }
        Command::Infrastructure { servers, format } => {
            infrastructure(&args.db, servers, format)
        }
        Command::Preflight { server, operation } => {
            preflight(&args.db, server, operation)
        }
        Command::Snapshot => {
            snapshot(&args.db).await
        }
    }
}

async fn snapshot(db_path: &std::path::Path) -> Result<()> {
    println!("Collecting system snapshot...");

    let snapshot = Collector::collect_snapshot().await?;
    let hostname = snapshot.hostname.clone();

    println!("  Hostname: {}", hostname);
    println!("  Listening services: {}", snapshot.listening_services.len());
    println!("  Network connections: {}", snapshot.network_connections.len());
    println!("  Processes: {}", snapshot.processes.len());
    println!("  Cron jobs: {}", snapshot.cron_jobs.len());
    println!("  Systemd timers: {}", snapshot.systemd_timers.len());

    let db = Database::new(db_path)?;
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

    let db = Database::new(db_path)?;
    let start = std::time::Instant::now();

    loop {
        match Collector::collect_snapshot().await {
            Ok(snapshot) => {
                db.store_snapshot(&snapshot)?;

                println!(
                    "[{}] Snapshot collected: {} services, {} connections",
                    chrono::Local::now().format("%H:%M:%S"),
                    snapshot.listening_services.len(),
                    snapshot.network_connections.len()
                );
            }
            Err(e) => eprintln!("Error collecting snapshot: {}", e),
        }

        if start.elapsed() >= duration {
            break;
        }

        time::sleep(interval).await;
    }

    println!("\nObservation complete. Run 'screamless report' to analyze.");
    Ok(())
}

fn report(db_path: &std::path::Path, hostname: Option<String>, format: String) -> Result<()> {
    let db = Database::new(db_path)?;
    let reporter = Reporter::new(&db);

    match format.as_str() {
        "json" => reporter.report_json(&hostname)?,
        "text" | _ => reporter.report_text(&hostname)?,
    }

    Ok(())
}

fn decommission_check(db_path: &std::path::Path, hostname: Option<String>) -> Result<()> {
    let db = Database::new(db_path)?;
    let reporter = Reporter::new(&db);
    reporter.decommission_check(&hostname)?;
    Ok(())
}

fn parse_duration(s: &str) -> Result<Duration> {
    let re = regex::Regex::new(r"^(\d+)([smhd])$")?;

    let caps = re.captures(s)
        .ok_or_else(|| anyhow::anyhow!("Invalid duration format: {}. Use format like '1h', '30m', '1d'", s))?;

    let value: u64 = caps[1].parse()?;
    let unit = &caps[2];

    let duration = match unit {
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value * 60),
        "h" => Duration::from_secs(value * 3600),
        "d" => Duration::from_secs(value * 86400),
        _ => unreachable!(),
    };

    Ok(duration)
}

fn dashboard(db_path: &std::path::Path, hostname: Option<String>, output: Option<std::path::PathBuf>) -> Result<()> {
    use crate::analysis::Analyzer;
    use crate::graph::GraphRenderer;

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

    let output_path = output.unwrap_or_else(|| std::path::PathBuf::from("screamless-dashboard.html"));

    let html = crate::dashboard::render_dashboard(&hostname, &analysis)?;
    std::fs::write(&output_path, html)?;

    println!("Dashboard generated: {}", output_path.display());
    println!("Open in browser to view interactive dependency analysis.");

    Ok(())
}

fn infrastructure(db_path: &std::path::Path, servers: String, format: String) -> Result<()> {
    use crate::analysis::Analyzer;
    use crate::infrastructure::InfrastructureMapper;
    use std::collections::HashMap;

    let db = Database::new(db_path)?;
    let analyzer = Analyzer::new(&db);

    let server_list: Vec<&str> = servers.split(',').map(|s| s.trim()).collect();
    let mut server_analyses = HashMap::new();

    println!("\nAnalyzing {} servers...\n", server_list.len());

    for server in server_list {
        match analyzer.analyze(server, 168) {
            Ok(analysis) => {
                println!("  ✓ {}", server);
                server_analyses.insert(server.to_string(), (analysis, vec![]));
            }
            Err(e) => {
                eprintln!("  ✗ {}: {}", server, e);
            }
        }
    }

    let chains = InfrastructureMapper::build_full_dependency_graph(&server_analyses);
    let single_points = InfrastructureMapper::find_single_points_of_failure(&chains);
    let clusters = InfrastructureMapper::find_dependency_clusters(&chains);

    println!("\n╭──────────────────────────────────────────╮");
    println!("│   INFRASTRUCTURE DEPENDENCY MAP          │");
    println!("╰──────────────────────────────────────────╯\n");

    println!("Servers analyzed: {}\n", server_analyses.len());

    if !single_points.is_empty() {
        println!("⚠️  SINGLE POINTS OF FAILURE:");
        for server in single_points {
            println!("  ✗ {} (shutdown would impact multiple services)", server);
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

    if format == "json" {
        println!("\n{}", serde_json::to_string_pretty(&server_analyses)?);
    }

    Ok(())
}

fn preflight(db_path: &std::path::Path, server: String, operation: String) -> Result<()> {
    use crate::analysis::Analyzer;

    let db = Database::new(db_path)?;
    let analyzer = Analyzer::new(&db);
    let analysis = analyzer.analyze(&server, 168)?;

    println!("\n╭──────────────────────────────────────────╮");
    println!("│   PREFLIGHT SAFETY CHECK                 │");
    println!("╰──────────────────────────────────────────╯\n");

    println!("Server: {}", server);
    println!("Operation: {}\n", operation);

    let mut safe = true;
    let mut warnings = Vec::new();

    match operation.as_str() {
        "restart" | "reboot" => {
            if !analysis.inbound_dependencies.is_empty() {
                warnings.push(format!(
                    "{} servers depend on this one (will lose connectivity during restart)",
                    analysis.inbound_dependencies.len()
                ));
                safe = false;
            }
            if analysis.decommission_confidence < 70 {
                warnings.push("Active dependencies detected, restart may cause issues".to_string());
                safe = false;
            }
        }
        "update" => {
            if !analysis.dependencies.is_empty() {
                let high_conf = analysis.dependencies.iter().filter(|d| d.confidence >= 70).count();
                if high_conf > 0 {
                    warnings.push(format!(
                        "{} high-confidence external dependencies",
                        high_conf
                    ));
                }
            }
        }
        "shutdown" => {
            if !analysis.inbound_dependencies.is_empty() {
                warnings.push(format!(
                    "CRITICAL: {} servers depend on this one",
                    analysis.inbound_dependencies.len()
                ));
                safe = false;
            }
            if !analysis.dependencies.is_empty() {
                warnings.push(format!(
                    "This server depends on {} external services",
                    analysis.dependencies.len()
                ));
            }
        }
        _ => {
            println!("Unknown operation: {}", operation);
        }
    }

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

    Ok(())
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
