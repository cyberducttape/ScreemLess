use anyhow::Result;
use crate::models::AnalysisResult;

pub fn render_dashboard(hostname: &str, analysis: &AnalysisResult) -> Result<String> {
    let deps_json = serde_json::to_string(&analysis.dependencies)?;
    let risks_json = serde_json::to_string(&analysis.risks)?;
    let readiness = analysis.decommission_confidence;

    let readiness_class = if readiness >= 80 {
        "ready"
    } else if readiness >= 50 {
        "caution"
    } else {
        "not-ready"
    };

    let readiness_status = if readiness >= 80 {
        "READY for decommission"
    } else if readiness >= 50 {
        "CAUTION - Review items before proceeding"
    } else {
        "NOT READY - Blocking issues detected"
    };

    let high_conf_count = analysis.dependencies.iter().filter(|d| d.confidence >= 70).count();
    let total_deps = analysis.dependencies.len();

    let deps_html = if total_deps == 0 {
        "<p style='color: #999; font-size: 12px;'>No outbound dependencies detected</p>".to_string()
    } else {
        analysis.dependencies.iter().take(10).map(|dep| {
            let display_addr = if let Some(ref h) = dep.hostname {
                format!("{} ({})", h, dep.remote_addr)
            } else {
                dep.remote_addr.clone()
            };
            format!(
                "<div class='dependency'><div class='dep-host'>{}:{} <span class='dep-confidence'>{}%</span></div><div class='dep-process'>{}</div></div>",
                display_addr,
                dep.remote_port,
                dep.confidence,
                dep.processes.join(", ")
            )
        }).collect::<Vec<_>>().join("")
    };

    let risks_html = if analysis.risks.is_empty() {
        "<p style='color: #999; font-size: 12px;'>No risks identified</p>".to_string()
    } else {
        analysis.risks.iter().take(5).map(|risk| {
            let risk_class = if matches!(risk.severity, crate::models::RiskSeverity::Fail) { "fail" } else { "" };
            format!(
                "<div class='risk {}'><div class='risk-name'>{}</div><div class='risk-desc'>{}</div></div>",
                risk_class, risk.name, risk.description
            )
        }).collect::<Vec<_>>().join("")
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Screamless: {}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
        }}

        header p {{
            font-size: 14px;
            opacity: 0.9;
        }}

        .readiness-banner {{
            background: white;
            padding: 20px;
            text-align: center;
            border-bottom: 3px solid #ddd;
        }}

        .readiness-score {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 120px;
            height: 120px;
            border-radius: 50%;
            font-size: 48px;
            font-weight: bold;
            color: white;
            margin: 0 auto 10px;
        }}

        .readiness-score.ready {{
            background: #4CAF50;
        }}

        .readiness-score.caution {{
            background: #FF9800;
        }}

        .readiness-score.not-ready {{
            background: #F44336;
        }}

        .readiness-status {{
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }}

        .main-content {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            padding: 30px;
        }}

        .section {{
            background: #f5f5f5;
            border-radius: 8px;
            padding: 20px;
        }}

        .section h2 {{
            font-size: 18px;
            margin-bottom: 15px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .graph-container {{
            background: white;
            border-radius: 8px;
            height: 500px;
            border: 1px solid #ddd;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #999;
        }}

        .dependency {{
            background: white;
            border-left: 4px solid #667eea;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .dependency:hover {{
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            transform: translateX(4px);
        }}

        .dep-host {{
            font-weight: 600;
            color: #667eea;
            font-size: 14px;
        }}

        .dep-confidence {{
            display: inline-block;
            font-size: 12px;
            background: #667eea;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            margin-left: 8px;
        }}

        .dep-process {{
            font-size: 12px;
            color: #666;
            margin-top: 4px;
        }}

        .risk {{
            background: white;
            border-left: 4px solid #ff9800;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
        }}

        .risk.fail {{
            border-left-color: #f44336;
        }}

        .risk-name {{
            font-weight: 600;
            color: #333;
            font-size: 14px;
        }}

        .risk-desc {{
            font-size: 12px;
            color: #666;
            margin-top: 4px;
        }}

        .stats {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 15px;
        }}

        .stat-box {{
            background: white;
            padding: 12px;
            border-radius: 4px;
            text-align: center;
            border: 1px solid #ddd;
        }}

        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }}

        .stat-label {{
            font-size: 11px;
            color: #999;
            margin-top: 4px;
        }}

        @media (max-width: 1024px) {{
            .main-content {{
                grid-template-columns: 1fr;
            }}

            .graph-container {{
                height: 400px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Screamless Dependency Analysis</h1>
            <p>Server: <strong>{}</strong></p>
        </header>

        <div class="readiness-banner">
            <div class="readiness-score {}">{}</div>
            <div class="readiness-status">
                {}
            </div>
        </div>

        <div class="main-content">
            <div>
                <div class="section">
                    <h2>Dependency Graph</h2>
                    <div class="graph-container" id="graph">
                        Interactive graph visualization
                    </div>
                </div>
            </div>

            <div>
                <div class="section">
                    <h2>Outbound Dependencies</h2>
                    <div id="dependencies">
                        {}
                    </div>
                    <div class="stats">
                        <div class="stat-box">
                            <div class="stat-value">{}</div>
                            <div class="stat-label">Total</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">{}</div>
                            <div class="stat-label">High Conf</div>
                        </div>
                    </div>
                </div>

                <div class="section" style="margin-top: 20px;">
                    <h2>Risks & Warnings</h2>
                    <div id="risks">
                        {}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const dependencies = {};
        const risks = {{}};
        console.log('Dependencies loaded:', dependencies);
    </script>
</body>
</html>"#,
        hostname,
        readiness_class,
        readiness,
        readiness_status,
        deps_html,
        total_deps,
        high_conf_count,
        risks_html,
        deps_json,
        risks_json
    );

    Ok(html)
}
