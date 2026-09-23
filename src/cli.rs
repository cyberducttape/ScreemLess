use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::PathBuf;
use tokio::time::{self, Duration};

use crate::collector::Collector;
use crate::db::Database;
use crate::report::Reporter;

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
        /// Observation duration (e.g. "1h", "30m", "24h")
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
    let duration = parse_duration(&duration.unwrap_or_else(|| "24h".to_string()))?;
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
