use anyhow::Result;
use serde_json::json;
use crate::db::Database;
use crate::models::*;

pub struct Reporter<'a> {
    db: &'a Database,
}

impl<'a> Reporter<'a> {
    pub fn new(db: &'a Database) -> Self {
        Reporter { db }
    }

    pub fn report_text(&self, hostname: &Option<String>) -> Result<()> {
        let hostname = self.resolve_hostname(hostname)?;

        if let Some(snapshot) = self.db.get_latest_snapshot(&hostname)? {
            println!("\n╭─────────────────────────────────────────╮");
            println!("│  SCREAMLESS OBSERVATION REPORT          │");
            println!("╰─────────────────────────────────────────╯\n");

            println!("SERVER: {}", snapshot.hostname);
            println!("SNAPSHOT: {}\n", snapshot.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));

            self.print_listening_services(&snapshot)?;
            self.print_network_connections(&snapshot)?;
            self.print_cron_jobs(&snapshot)?;
            self.print_systemd_timers(&snapshot)?;
        } else {
            println!("No observations found for {}", hostname);
        }

        Ok(())
    }

    pub fn report_json(&self, hostname: &Option<String>) -> Result<()> {
        let hostname = self.resolve_hostname(hostname)?;

        if let Some(snapshot) = self.db.get_latest_snapshot(&hostname)? {
            let json = json!({
                "server": snapshot.hostname,
                "timestamp": snapshot.timestamp.to_rfc3339(),
                "listening_services": snapshot.listening_services,
                "network_connections": snapshot.network_connections,
                "cron_jobs": snapshot.cron_jobs,
                "systemd_timers": snapshot.systemd_timers,
            });

            println!("{}", serde_json::to_string_pretty(&json)?);
        } else {
            println!("{{}}");
        }

        Ok(())
    }

    pub fn decommission_check(&self, hostname: &Option<String>) -> Result<()> {
        let hostname = self.resolve_hostname(hostname)?;

        println!("\n╭──────────────────────────────────────────╮");
        println!("│   DECOMMISSION READINESS REPORT          │");
        println!("╰──────────────────────────────────────────╯\n");

        if let Some(snapshot) = self.db.get_latest_snapshot(&hostname)? {
            println!("Server: {}", snapshot.hostname);
            println!("Last observation: {}\n", snapshot.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));

            let mut concerns = Vec::new();
            let mut ready_items = Vec::new();

            // Check for listening services
            if snapshot.listening_services.is_empty() {
                ready_items.push("[PASS] No listening services");
            } else {
                concerns.push(format!(
                    "[WARN] {} listening services found",
                    snapshot.listening_services.len()
                ));
            }

            // Check for active connections
            if snapshot.network_connections.is_empty() {
                ready_items.push("[PASS] No active network connections");
            } else {
                concerns.push(format!(
                    "[WARN] {} active connections found",
                    snapshot.network_connections.len()
                ));
            }

            // Check for cron jobs
            if snapshot.cron_jobs.is_empty() {
                ready_items.push("[PASS] No cron jobs");
            } else {
                concerns.push(format!(
                    "[WARN] {} cron jobs found",
                    snapshot.cron_jobs.len()
                ));
            }

            // Check for systemd timers
            if snapshot.systemd_timers.is_empty() {
                ready_items.push("[PASS] No systemd timers");
            } else {
                concerns.push(format!(
                    "[WARN] {} systemd timers found",
                    snapshot.systemd_timers.len()
                ));
            }

            let readiness_count = ready_items.len();
            let total_checks = ready_items.len() + concerns.len();

            for item in &ready_items {
                println!("{}", item);
            }

            for concern in &concerns {
                println!("{}", concern);
            }

            let readiness = if total_checks == 0 { 0 } else { (readiness_count * 100) / total_checks };
            println!("\nReadiness: {}%", readiness);

            if readiness < 100 {
                println!("\nNOT READY for decommission.\n");
                println!("Items to investigate:");
                for (i, service) in snapshot.listening_services.iter().enumerate() {
                    println!("  {}. Service {} listening on :{}", i + 1, service.process_name, service.port);
                }
                for (i, conn) in snapshot.network_connections.iter().take(5).enumerate() {
                    println!("  {}. Connection from {}:{} to {}:{}", i + 1, conn.local_addr, conn.local_port, conn.remote_addr, conn.remote_port);
                }
            } else {
                println!("\nREADY for decommission.");
            }
        } else {
            println!("No observations found for {}. Run 'screamless observe' first.", hostname);
        }

        Ok(())
    }

    fn print_listening_services(&self, snapshot: &ObservationSnapshot) -> Result<()> {
        if snapshot.listening_services.is_empty() {
            return Ok(());
        }

        println!("LISTENING SERVICES");
        for service in &snapshot.listening_services {
            println!("  :{:<5} {} (PID: {}, User: {})",
                service.port,
                service.process_name,
                service.pid,
                service.user
            );
        }
        println!();

        Ok(())
    }

    fn print_network_connections(&self, snapshot: &ObservationSnapshot) -> Result<()> {
        if snapshot.network_connections.is_empty() {
            return Ok(());
        }

        println!("NETWORK CONNECTIONS (ESTABLISHED)");
        for conn in snapshot.network_connections.iter().take(20) {
            println!("  {}:{} -> {}:{} ({})",
                conn.local_addr,
                conn.local_port,
                conn.remote_addr,
                conn.remote_port,
                conn.process_name
            );
        }

        if snapshot.network_connections.len() > 20 {
            println!("  ... and {} more",
                snapshot.network_connections.len() - 20
            );
        }
        println!();

        Ok(())
    }

    fn print_cron_jobs(&self, snapshot: &ObservationSnapshot) -> Result<()> {
        if snapshot.cron_jobs.is_empty() {
            return Ok(());
        }

        println!("CRON JOBS");
        let mut by_source: std::collections::BTreeMap<&str, Vec<_>> =
            std::collections::BTreeMap::new();

        for job in &snapshot.cron_jobs {
            by_source.entry(&job.source).or_insert_with(Vec::new).push(job);
        }

        for (source, jobs) in by_source {
            println!("  {} ({})", source, jobs.len());
            for job in jobs.iter().take(3) {
                println!("    {}", job.command);
            }
            if jobs.len() > 3 {
                println!("    ... and {} more", jobs.len() - 3);
            }
        }
        println!();

        Ok(())
    }

    fn print_systemd_timers(&self, snapshot: &ObservationSnapshot) -> Result<()> {
        if snapshot.systemd_timers.is_empty() {
            return Ok(());
        }

        println!("SYSTEMD TIMERS");
        for timer in snapshot.systemd_timers.iter().take(10) {
            let status = if timer.active { "active" } else { "inactive" };
            println!("  {} [{}]", timer.unit, status);
        }

        if snapshot.systemd_timers.len() > 10 {
            println!("  ... and {} more", snapshot.systemd_timers.len() - 10);
        }
        println!();

        Ok(())
    }

    fn resolve_hostname(&self, hostname: &Option<String>) -> Result<String> {
        if let Some(h) = hostname {
            Ok(h.clone())
        } else {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .or_else(|_| Ok("localhost".to_string()))
        }
    }
}
