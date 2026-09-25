# Changelog

## [1.0.0] - 2026-09-23

### Phase 1: Observability Foundation ✅
- Process collection from `/proc`
- Listening service detection via `ss`/`netstat`
- Network connection tracking
- Cron job discovery from `/etc/cron.*`
- Systemd timer detection
- Single snapshot capability
- SQLite persistence

### Phase 2: Dependency Inference ✅
- Outbound dependency detection
- Connection frequency analysis
- Temporal pattern detection
- Confidence scoring with evidence
- 7-day observation window default
- Risk assessment and categorization
- Decommission readiness scoring (0-100%)
- Text and JSON report formats

### Phase 3: Configuration Intelligence ✅
- Nginx upstream and proxy_pass parsing
- PHP-FPM configuration scanning
- Application config discovery (Django, Node.js, etc.)
- Database configuration parsing (MySQL, PostgreSQL)
- Environment variable analysis
- DNS hostname resolution
- ASCII dependency graph visualization
- Config line extraction for evidence

### Phase 4: Interactive Dashboard ✅
- Beautiful self-contained HTML generation
- Browser-native interactive dependency graphs
- Color-coded readiness assessment
- Real-time statistics
- Responsive mobile-friendly design
- Drag-and-drop interactive nodes
- Single-file distribution (works offline)

### Phase 5: Reverse Dependency Inference ✅
**THE LEGENDARY FEATURE**
- DNS record detection (who is this server known as?)
- Access log analysis (who connects to me?)
- SSH authorized_keys scanning (who has access?)
- Git configuration parsing (who clones/references me?)
- Central observed-edge reversal for inbound dependency mapping
- /etc/hosts entry discovery (who hardcoded reference to me?)
- Impact level classification (CRITICAL/HIGH/MEDIUM/LOW)
- Inbound dependency display in reports

### Phase 6: Infrastructure Mapping ✅
- Multi-server dependency graph building
- Single point of failure detection
- Dependency cluster identification
- Cascade failure impact analysis
- Cross-infrastructure visualization
- Shutdown impact predictions
- Infrastructure-wide "what if" analysis

### Phase 7: Automation & CI/CD Integration ✅
- Pre-flight safety checks
- Operation validation (restart, update, shutdown)
- Exit codes for pipeline integration
- Deployment pipeline compatibility
- Automated risk assessment
- Safety gates for infrastructure changes

### Phase 8: Distribution & Documentation ✅
- One-command installation script
- Comprehensive quick start guide
- Real-world scenario documentation
- CI/CD integration examples
- Troubleshooting guide
- Production deployment patterns
- Version 1.0 release readiness

## Features Summary

### Observation & Collection
- Lightweight process monitoring
- Non-intrusive network observation
- Configuration file discovery
- Historical tracking (7+ days)

### Analysis
- Outbound dependency inference
- Inbound dependency detection
- Confidence scoring
- Risk categorization
- Impact analysis
- Cascade failure prediction

### Reporting
- Text reports with ASCII graphs
- JSON for automation
- Interactive HTML dashboards
- Decommission readiness assessment
- Infrastructure-wide mapping

### Safety
- Pre-flight operation validation
- Dependency verification
- Evidence-based claims
- Confidence transparency
- Risk level indicators

### Deployment
- Single binary distribution
- One-script installation
- No external dependencies
- Privacy-first design
- Works offline

## Design Philosophy

**Screamless is legendary because it:**

1. **Solves the real problem**: Not "what services run here?" but "what breaks if I change this?"

2. **Shows evidence**: Every dependency claim includes proof (observed connections, config references, DNS records)

3. **Works immediately**: Deploy anywhere, no setup, first results in minutes (or days for comprehensive view)

4. **Is honest**: Confidence scores and impact levels prevent false confidence

5. **Stays safe**: Never breaks anything, only observes

6. **Scales anywhere**: Works on single server or entire infrastructure

## Known Limitations & Future Work

- IPv6 support can be enhanced
- Container/Kubernetes detection in roadmap
- Reverse DNS lookups (Phase 9 enhancement)
- Historical trending dashboard (Phase 10)
- Peer-peer dependency clustering (Phase 11)

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/anthropics/screamless/main/install.sh | bash
```

## Upgrade Path

From earlier versions: Just reinstall with install.sh

## Breaking Changes

None - this is version 1.0.0 (production first release)

## Credits

Built by infrastructure engineers, for infrastructure engineers who are tired of the scream test.

---

**Stop the scream test. Use Screamless.**
