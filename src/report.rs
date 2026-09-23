use anyhow::Result;
use serde_json::json;
use crate::db::Database;
use crate::models::*;
use crate::analysis::Analyzer;
use crate::graph::GraphRenderer;

pub struct Reporter<'a> {
    db: &'a Database,
}

impl<'a> Reporter<'a> {
    pub fn new(db: &'a Database) -> Self {
        Reporter { db }
    }

    pub fn report_text(&self, hostname: &Option<String>) -> Result<()> {
        let hostname = self.resolve_hostname(hostname)?;
        let analyzer = Analyzer::new(self.db);

        let analysis = analyzer.analyze(&hostname, 168)?;

        if analysis.total_snapshots == 0 {
            println!("No observations found for {}. Run 'screamless observe' first.", hostname);
            return Ok(());
        }

        println!("\n╭──────────────────────────────────────────────────╮");
        println!("│  SCREAMLESS ANALYSIS REPORT                      │");
        println!("╰──────────────────────────────────────────────────╯\n");

        println!("SERVER: {}", hostname);
        println!(
            "OBSERVATION PERIOD: {} to {}",
            analysis.observation_span.0.format("%Y-%m-%d %H:%M:%S UTC"),
            analysis.observation_span.1.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("SNAPSHOTS: {}\n", analysis.total_snapshots);

        println!("DEPENDENCY GRAPH");
        println!("{}", GraphRenderer::render_ascii(&analysis, &hostname));
        println!();

        self.print_dependencies(&analysis)?;
        self.print_risks(&analysis)?;
        self.print_summary(&analysis)?;

        Ok(())
    }

    pub fn report_json(&self, hostname: &Option<String>) -> Result<()> {
        let hostname = self.resolve_hostname(hostname)?;
        let analyzer = Analyzer::new(self.db);

        let analysis = analyzer.analyze(&hostname, 168)?;

        let json = json!({
            "server": hostname,
            "observation_period": {
                "start": analysis.observation_span.0.to_rfc3339(),
                "end": analysis.observation_span.1.to_rfc3339(),
                "hours": analysis.observation_window_hours,
            },
            "snapshots": analysis.total_snapshots,
            "dependencies": analysis.dependencies,
            "risks": analysis.risks,
            "decommission_confidence": analysis.decommission_confidence,
        });

        println!("{}", serde_json::to_string_pretty(&json)?);
        Ok(())
    }

    pub fn decommission_check(&self, hostname: &Option<String>) -> Result<()> {
        let hostname = self.resolve_hostname(hostname)?;
        let analyzer = Analyzer::new(self.db);

        let analysis = analyzer.analyze(&hostname, 168)?;

        println!("\n╭──────────────────────────────────────────────────╮");
        println!("│   DECOMMISSION READINESS REPORT                  │");
        println!("╰──────────────────────────────────────────────────╯\n");

        println!("Server: {}", hostname);
        println!(
            "Observation: {} snapshots over {} hours\n",
            analysis.total_snapshots, analysis.observation_window_hours
        );

        if analysis.total_snapshots == 0 {
            println!("No observations found. Run 'screamless observe' first.");
            return Ok(());
        }

        self.print_readiness_assessment(&analysis)?;
        self.print_decommission_risks(&analysis)?;

        println!(
            "\n╔════════════════════════════════════════════════════╗"
        );
        let readiness_str = format!("READINESS: {}%", analysis.decommission_confidence);
        println!(
            "║ {} ║",
            readiness_str.center(48)
        );
        println!(
            "╚════════════════════════════════════════════════════╝\n"
        );

        if analysis.decommission_confidence >= 80 {
            println!("✓ READY for decommission.\n");
            println!("All indicators are clear. Safe to proceed.");
        } else if analysis.decommission_confidence >= 50 {
            println!("⚠ CAUTION. Investigate remaining items before proceeding.\n");
            println!("Outstanding dependencies or scheduled jobs detected.");
        } else {
            println!("✗ NOT READY. Cannot decommission safely.\n");
            println!("Active dependencies or critical processes detected.");
        }

        Ok(())
    }

    fn print_dependencies(&self, analysis: &AnalysisResult) -> Result<()> {
        if analysis.dependencies.is_empty() {
            println!("OUTBOUND DEPENDENCIES: None detected\n");
            return Ok(());
        }

        println!("OUTBOUND DEPENDENCIES ({} found)", analysis.dependencies.len());

        for dep in analysis.dependencies.iter().take(15) {
            let display_name = if let Some(ref hostname) = dep.hostname {
                format!("{} ({})", hostname, dep.remote_addr)
            } else {
                dep.remote_addr.clone()
            };

            println!("\n  {}:{}", display_name, dep.remote_port);
            println!("  Confidence: {}%", dep.confidence);
            println!("  Connections: {} (first: {}, last: {})",
                dep.connection_count,
                dep.first_seen.format("%H:%M:%S"),
                dep.last_seen.format("%H:%M:%S")
            );

            if !dep.processes.is_empty() {
                println!("  Processes: {}", dep.processes.join(", "));
            }

            if !dep.config_references.is_empty() {
                println!("  Found in configuration:");
                for cfg in dep.config_references.iter().take(3) {
                    println!("    - {} ({})", cfg.file_path, cfg.context);
                }
                if dep.config_references.len() > 3 {
                    println!("    - ... and {} more", dep.config_references.len() - 3);
                }
            }

            if !dep.evidence.is_empty() {
                println!("  Evidence:");
                for ev in &dep.evidence {
                    println!("    [{}] {}",
                        format!("{:?}", ev.level).to_uppercase(),
                        ev.description
                    );
                }
            }
        }

        if analysis.dependencies.len() > 15 {
            println!("\n  ... and {} more dependencies", analysis.dependencies.len() - 15);
        }

        println!();
        Ok(())
    }

    fn print_risks(&self, analysis: &AnalysisResult) -> Result<()> {
        if analysis.risks.is_empty() {
            println!("RISKS: None identified\n");
            return Ok(());
        }

        println!("RISKS & WARNINGS");

        for (i, risk) in analysis.risks.iter().enumerate() {
            let marker = match risk.severity {
                RiskSeverity::Fail => "✗",
                RiskSeverity::Warn => "⚠",
                RiskSeverity::Info => "ℹ",
            };

            println!("\n  {} {}", marker, risk.name);
            println!("    {}", risk.description);
            println!("    Evidence: {}", risk.evidence);

            if i >= 9 {
                if analysis.risks.len() > 10 {
                    println!("\n  ... and {} more", analysis.risks.len() - 10);
                }
                break;
            }
        }

        println!();
        Ok(())
    }

    fn print_summary(&self, analysis: &AnalysisResult) -> Result<()> {
        println!("SUMMARY");
        println!("  Total outbound dependencies: {}", analysis.dependencies.len());
        println!("  High-confidence dependencies: {}",
            analysis.dependencies.iter().filter(|d| d.confidence >= 70).count()
        );
        println!("  Identified risks: {}", analysis.risks.len());

        Ok(())
    }

    fn print_readiness_assessment(&self, analysis: &AnalysisResult) -> Result<()> {
        let mut checks = Vec::new();

        if !analysis.dependencies.is_empty() {
            let high_conf = analysis.dependencies.iter()
                .filter(|d| d.confidence >= 70)
                .count();
            if high_conf > 0 {
                checks.push(format!("[FAIL] {} confirmed outbound dependencies", high_conf));
            } else {
                checks.push(format!("[WARN] {} low-confidence outbound dependencies", analysis.dependencies.len()));
            }
        } else {
            checks.push("[PASS] No outbound dependencies detected".to_string());
        }

        let critical_one_time = analysis.observed_processes
            .values()
            .filter(|p| p.only_once_in_window && (p.name.contains("backup") || p.name.contains("sync")))
            .count();

        if critical_one_time > 0 {
            checks.push(format!("[WARN] {} critical process(es) seen only once", critical_one_time));
        }

        if !analysis.risks.is_empty() {
            let fails = analysis.risks.iter().filter(|r| matches!(r.severity, RiskSeverity::Fail)).count();
            let warns = analysis.risks.iter().filter(|r| matches!(r.severity, RiskSeverity::Warn)).count();

            if fails > 0 {
                checks.push(format!("[FAIL] {} critical issues", fails));
            }
            if warns > 0 {
                checks.push(format!("[WARN] {} warnings", warns));
            }
        } else {
            checks.push("[PASS] No critical issues".to_string());
        }

        for check in checks {
            println!("  {}", check);
        }

        println!();
        Ok(())
    }

    fn print_decommission_risks(&self, analysis: &AnalysisResult) -> Result<()> {
        println!("BLOCKING ISSUES:");

        let mut any_blocking = false;

        for dep in analysis.dependencies.iter().filter(|d| d.confidence >= 70) {
            println!("  • {}:{} - {} confirmed connections from {}",
                dep.remote_addr,
                dep.remote_port,
                dep.connection_count,
                dep.processes.join(", ")
            );
            any_blocking = true;
        }

        for risk in analysis.risks.iter() {
            match risk.severity {
                RiskSeverity::Fail => {
                    println!("  • {} - {}", risk.name, risk.description);
                    any_blocking = true;
                }
                RiskSeverity::Warn => {
                    println!("  ⚠ {} - {}", risk.name, risk.description);
                }
                _ => {}
            }
        }

        if !any_blocking && analysis.dependencies.is_empty() {
            println!("  ✓ None - all systems clear");
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

trait StringCenter {
    fn center(&self, width: usize) -> String;
}

impl StringCenter for str {
    fn center(&self, width: usize) -> String {
        let len = self.len();
        if len >= width {
            self.to_string()
        } else {
            let left = (width - len) / 2;
            let right = width - len - left;
            format!("{}{}{}", " ".repeat(left), self, " ".repeat(right))
        }
    }
}
