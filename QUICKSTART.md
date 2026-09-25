# Screamless Quick Start Guide

## Installation

```bash
# Using install script (easiest)
curl -fsSL https://raw.githubusercontent.com/cyberducttape/ScreemLess/master/install.sh | bash

# Or build from source
git clone --branch master https://github.com/cyberducttape/ScreemLess
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
# Output: a readiness assessment; an empty result is not proof of no dependencies
```

### "Is it safe to restart db01 right now?"
```bash
screamless preflight --server db01 --operation restart
# Output: ⚠️ 15 servers depend on this, plan maintenance window
```

### "Review observed infrastructure relationships"
```bash
screamless infrastructure --servers web01,web02,db01,cache01,backup01
# Output: Shows observed relationships and potential single points of failure
```

### "Generate a shareable report"
```bash
screamless dashboard --output infrastructure-report.html
# Open in browser, share with team
```

## Multi-Server Observation

For best results, run the collector on each relevant host. This command
observes only the local host; there is no built-in remote collection or
multi-host ingest:
```bash
# Observe for up to 7 days (default)
screamless observe
# Let it run, or run in background:
screamless observe &
```

## Understanding Output

### Confidence Scores
- Scores summarize the evidence collected; they are not probabilities.
- An **OBSERVED** relationship is based on a socket seen by the local
  collector.
- A **DECLARED** relationship is supporting configuration evidence and does
  not prove that traffic occurred.
- **UNKNOWN** means a required probe was unavailable, permission restricted,
  or the observation window was inadequate.
- A low or empty result is not proof that no dependency exists.

### Readiness Score
- **80-100%**: no current blocker was found in the available evidence
- **50-79%**: caution; outstanding items require review
- **Below 50%**: blocking issues were found
- Any incomplete required probe produces an insufficient-evidence result and
  should be reviewed before treating a change as safe.

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

1. **Read the full README** for scope and limitations
2. **Try the dashboard** for local interactive visualization
3. **Share reports** with their probe status and observation window
4. **Integrate with CI/CD** only after defining how insufficient evidence is handled

## Support

- Issues: https://github.com/cyberducttape/ScreemLess/issues
- Documentation: README.md in repo
- Examples: See the examples in this guide and README.md

---

**Stop the scream test. Use Screamless.**
