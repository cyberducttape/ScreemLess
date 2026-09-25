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

        .graph-svg {{
            width: 100%;
            height: 100%;
            touch-action: none;
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
                        <svg class="graph-svg" id="graph-svg" role="img" aria-label="Interactive dependency graph"></svg>
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
        const localHostname = {};
        const dependencies = {};
        const risks = {};
        const graphElement = document.getElementById('graph');
        const svg = document.getElementById('graph-svg');
        const svgNamespace = 'http://www.w3.org/2000/svg';
        const nodes = [{{id: localHostname, local: true}}];
        const links = [];
        const nodeIds = new Set([localHostname]);

        dependencies.forEach(function (dependency) {{
            const target = (dependency.hostname || dependency.remote_addr) + ':' + dependency.remote_port;
            if (!nodeIds.has(target)) {{
                nodeIds.add(target);
                nodes.push({{id: target, local: false, confidence: dependency.confidence}});
            }}
            links.push({{source: localHostname, target: target, confidence: dependency.confidence}});
        }});

        function graphPoint(index, total, width, height) {{
            if (index === 0) return {{x: width / 2, y: height / 2}};
            const angle = ((index - 1) / Math.max(1, total - 1)) * Math.PI * 2;
            const radius = Math.min(width, height) * 0.32;
            return {{x: width / 2 + Math.cos(angle) * radius, y: height / 2 + Math.sin(angle) * radius}};
        }}

        const positions = new Map();
        function renderGraph() {{
            const width = graphElement.clientWidth;
            const height = graphElement.clientHeight;
            svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
            svg.replaceChildren();
            nodes.forEach(function (node, index) {{
                if (!positions.has(node.id)) positions.set(node.id, graphPoint(index, nodes.length, width, height));
            }});

            links.forEach(function (link) {{
                const line = document.createElementNS(svgNamespace, 'line');
                line.setAttribute('class', 'graph-link');
                line.dataset.source = link.source;
                line.dataset.target = link.target;
                line.dataset.confidence = link.confidence;
                svg.appendChild(line);
            }});

            nodes.forEach(function (node) {{
                const group = document.createElementNS(svgNamespace, 'g');
                const circle = document.createElementNS(svgNamespace, 'circle');
                const label = document.createElementNS(svgNamespace, 'text');
                circle.setAttribute('r', node.local ? '18' : '12');
                circle.setAttribute('fill', node.local ? '#667eea' : '#764ba2');
                label.textContent = node.id;
                label.setAttribute('x', node.local ? '22' : '16');
                label.setAttribute('y', '4');
                label.setAttribute('font-size', '12');
                label.setAttribute('fill', '#333');
                group.appendChild(circle);
                group.appendChild(label);
                group.dataset.nodeId = node.id;
                group.style.cursor = 'grab';
                group.addEventListener('pointerdown', function (event) {{
                    event.preventDefault();
                    group.setPointerCapture(event.pointerId);
                    group.style.cursor = 'grabbing';
                    const move = function (moveEvent) {{
                        const point = svg.createSVGPoint();
                        point.x = moveEvent.clientX;
                        point.y = moveEvent.clientY;
                        const localPoint = point.matrixTransform(svg.getScreenCTM().inverse());
                        positions.set(node.id, {{x: localPoint.x, y: localPoint.y}});
                        renderGraph();
                    }};
                    const end = function () {{
                        group.style.cursor = 'grab';
                        group.removeEventListener('pointermove', move);
                        group.removeEventListener('pointerup', end);
                    }};
                    group.addEventListener('pointermove', move);
                    group.addEventListener('pointerup', end);
                }});
                svg.appendChild(group);
            }});

            Array.from(svg.querySelectorAll('line')).forEach(function (line) {{
                const source = positions.get(line.dataset.source);
                const target = positions.get(line.dataset.target);
                line.setAttribute('x1', source.x);
                line.setAttribute('y1', source.y);
                line.setAttribute('x2', target.x);
                line.setAttribute('y2', target.y);
                line.setAttribute('stroke', '#aaa');
                line.setAttribute('stroke-width', '2');
            }});
            Array.from(svg.querySelectorAll('g')).forEach(function (group) {{
                const position = positions.get(group.dataset.nodeId);
                group.setAttribute('transform', 'translate(' + position.x + ',' + position.y + ')');
            }});
        }}

        renderGraph();
        window.addEventListener('resize', renderGraph);
    </script>
</body>
</html>"#,
        hostname,
        hostname,
        readiness_class,
        readiness,
        readiness_status,
        deps_html,
        total_deps,
        high_conf_count,
        risks_html,
        serde_json::to_string(hostname)?,
        deps_json,
        risks_json
    );

    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::render_dashboard;
    use crate::models::*;
    use chrono::Utc;

    #[test]
    fn renders_dashboard_values_in_their_expected_fields() {
        let now = Utc::now();
        let analysis = AnalysisResult {
            observation_window_hours: 1,
            total_snapshots: 1,
            observation_span: (now, now),
            dependencies: vec![Dependency {
                remote_addr: "10.0.0.2".to_string(),
                remote_port: 3306,
                protocol: "tcp".to_string(),
                connection_count: 3,
                first_seen: now,
                last_seen: now,
                processes: vec!["billing".to_string()],
                confidence: 85,
                evidence: Vec::new(),
                config_references: Vec::new(),
                hostname: Some("db01".to_string()),
            }],
            inbound_dependencies: Vec::new(),
            observed_processes: std::collections::HashMap::new(),
            risks: vec![RiskAssessment {
                name: "Example risk".to_string(),
                severity: RiskSeverity::Warn,
                description: "Example description".to_string(),
                evidence: "Example evidence".to_string(),
            }],
            decommission_confidence: 85,
            probe_statuses: ProbeStatuses::default(),
        };

        let html = render_dashboard("db01", &analysis).unwrap();
        assert!(html.contains("<title>Screamless: db01</title>"));
        assert!(html.contains("<p>Server: <strong>db01</strong></p>"));
        assert!(html.contains("<div class=\"readiness-score ready\">85</div>"));
        assert!(html.contains("READY for decommission"));
        assert!(html.contains("const dependencies = [{"));
        assert!(html.contains("const risks = [{"));
        assert!(html.contains("Example risk"));
        assert!(html.contains("addEventListener('pointerdown'"));
        assert!(!html.contains("cdnjs.cloudflare.com"));
    }
}
