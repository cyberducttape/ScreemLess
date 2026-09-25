# Screamless Quick Start Guide

## Installation

```bash
# Using install script (easiest)
curl -fsSL https://raw.githubusercontent.com/anthropics/screamless/main/install.sh | bash

# Or build from source
git clone https://github.com/anthropics/screamless
cd screamless
cargo build --release
sudo cp target/release/screamless /usr/local/bin/
```

## 5-Minute Quick Start

### 1. Take a single snapshot
```bash
screamless snapshot
```
This collects one observation of your system.

### 2. Generate a report
```bash
screamless report
```
Shows what this server connects to and what connects to it.

### 3. Check if safe to decommission
```bash
screamless decommission-check
```
Gives a readiness score (0-100%).

## Real-World Scenarios

### "Can we shut down web-old-03?"
```bash
screamless decommission-check --hostname web-old-03
# Output: 92% ready, no dependencies detected
```

### "Is it safe to restart db01 right now?"
```bash
screamless preflight --server db01 --operation restart
# Output: ⚠️ 15 servers depend on this, plan maintenance window
```

### "Map our entire infrastructure"
```bash
screamless infrastructure --servers web01,web02,db01,cache01,backup01
# Output: Shows single points of failure, clusters, dependencies
```

### "Generate a shareable report"
```bash
screamless dashboard --output infrastructure-report.html
# Open in browser, share with team
```

## Multi-Server Observation

For best results (catches all dependencies):
```bash
# Observe for 7 days (default)
screamless observe
# Let it run, or run in background:
screamless observe &
```

## Understanding Output

### Confidence Scores
- **95-100%**: Very high confidence (many observations or config reference)
- **80-94%**: High confidence (consistent observations)
- **60-79%**: Medium confidence (some evidence)
- **Below 60%**: Low confidence (needs more observation)

### Readiness Score
- **80-100%**: READY for decommission/change
- **50-79%**: CAUTION - has outstanding items
- **Below 50%**: NOT READY - blocking issues exist

### Impact Levels
- **CRITICAL**: Will break immediately if this server goes down
- **HIGH**: Will lose functionality
- **MEDIUM**: May have issues
- **LOW**: Minimal impact

## Troubleshooting

### "No dependencies detected"
- Observation window too short (increase to 7+ days)
- Services not actively communicating during window
- Check inbound dependencies for reverse dependencies

### "High confidence mismatch with reality"
- Config file has unused reference (check if actually used)
- DNS record exists but service deprecated
- Validate with network team

### "Performance issues on large systems"
- Screamless is lightweight, but analyzing 10,000+ connections takes time
- Run observations during off-peak
- Use background mode: `screamless observe &`

Observation uses periodic TCP/UDP polling, so very short-lived network activity may not be captured. The observer prunes snapshots older than 30 days.

## Integration

### With CI/CD (GitLab, GitHub Actions)
```yaml
# Before deployment:
- screamless preflight --server app01 --operation update
```
Exit codes:
- `0` = safe
- `1` = unsafe (blocks merge)
- `2` = insufficient evidence
- `3` = invalid invocation

Use `--json` for a stable machine-readable result:

```bash
screamless preflight --server app01 --operation update --json
```

### With Ansible/Terraform
```bash
# Pre-flight check in playbook
- name: Safety check before reboot
  command: screamless preflight --server {{ inventory_hostname }} --operation restart
```

## Next Steps

1. **Read the full README** for comprehensive feature list
2. **Try the dashboard** for interactive visualization
3. **Share reports** with your infrastructure team
4. **Integrate with CI/CD** for automated safety gates

## Support

- Issues: https://github.com/anthropics/screamless/issues
- Documentation: README.md in repo
- Examples: See EXAMPLES.md

---

**Stop the scream test. Use Screamless.**
