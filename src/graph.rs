use crate::models::{Dependency, AnalysisResult};

pub struct GraphRenderer;

impl GraphRenderer {
    pub fn render_ascii(analysis: &AnalysisResult, hostname: &str) -> String {
        if analysis.dependencies.is_empty() {
            return format!(
                "  ┌─────────────┐\n  │   {}   │\n  └─────────────┘\n  (no outbound dependencies)\n",
                hostname
            );
        }

        let mut output = String::new();

        output.push_str("  ┌──────────────────────┐\n");
        output.push_str(&format!("  │  {} (local)  │\n", hostname));
        output.push_str("  └──────────────────────┘\n");

        let mut group_by_port: std::collections::BTreeMap<u16, Vec<&Dependency>> =
            std::collections::BTreeMap::new();

        for dep in &analysis.dependencies {
            group_by_port
                .entry(dep.remote_port)
                .or_insert_with(Vec::new)
                .push(dep);
        }

        let mut is_first_group = true;

        for (port, deps) in group_by_port {
            if !is_first_group {
                output.push('\n');
            }
            is_first_group = false;

            output.push_str("         ↓\n");

            for (i, dep) in deps.iter().enumerate() {
                let is_last = i == deps.len() - 1;
                let branch = if is_last { "└──" } else { "├──" };
                let connection = if is_last { "    " } else { "│   " };

                let display_name = if let Some(ref hostname) = dep.hostname {
                    format!("{} ({}:{})", hostname, dep.remote_addr, port)
                } else {
                    format!("{}:{}", dep.remote_addr, port)
                };

                output.push_str(&format!(
                    "  {} ┌─ {} [{}%]\n",
                    branch, display_name, dep.confidence
                ));

                if !dep.processes.is_empty() {
                    let procs = dep.processes.join(", ");
                    output.push_str(&format!(
                        "  {}   └─ via: {}\n",
                        connection, procs
                    ));
                }
            }
        }

        output
    }

    pub fn render_summary_stats(analysis: &AnalysisResult) -> String {
        let total = analysis.dependencies.len();
        let high_conf = analysis
            .dependencies
            .iter()
            .filter(|d| d.confidence >= 70)
            .count();
        let med_conf = analysis
            .dependencies
            .iter()
            .filter(|d| d.confidence >= 50 && d.confidence < 70)
            .count();

        format!(
            "Dependencies: {} total ({} high confidence, {} medium confidence)",
            total, high_conf, med_conf
        )
    }
}
