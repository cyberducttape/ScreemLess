# Screamless: The Server Archaeology Tool

> **"Stop the Scream Test. Use Screamless Instead."**

## The Problem

Every sysadmin faces this nightmare:

- "Can we decommission web-old-03?" 
- "I dunno, let's shut it down and see what breaks."

This is the **scream test** — and it's how most infrastructure changes happen in 2026.

The real questions are:
- *What other servers depend on me?*
- *Will shutting me down break anyone?*
- *What am I actually used for?*

Most servers have **no documentation**. You inherit them. Nobody knows why they still exist.

## The Solution: Screamless

**Automatic dependency archaeology.** In 7 days of passive observation, Screamless tells you:

1. **What this server connects to** (outbound dependencies)
2. **What connects to this server** (inbound dependencies) 
3. **Confidence scores for each** (with evidence)
4. **Impact if you shut it down** (cascade analysis)
5. **Single points of failure** (across your infrastructure)

## Quick Start

```bash
# Build
cargo build --release

# Observe for 7 days (the default)
./target/release/screamless observe

# Generate report
./target/release/screamless report

# Check if safe to decommission
./target/release/screamless decommission-check

# Check before deployment/restart
./target/release/screamless preflight --server db01 --operation restart

# Interactive dashboard
./target/release/screamless dashboard --output analysis.html
```

## What It Tells You

### Outbound Dependencies
```
Web server connects to:
  db01:3306           94% confidence (42 connections, nginx process, wp-config.php reference)
  redis01:6379        87% confidence (15 connections, php-fpm process)
  api.vendor.com:443  61% confidence (2 connections, config reference only)
```

### Inbound Dependencies  
```
These servers depend on THIS one:
  web01        95% confidence (observed outbound connections to this server)
  monitor01    92% confidence (observed outbound connections to this server)
```

Process activity counts snapshots in which a process was observed; it does not claim to count process executions. Cron discovery parses schedules from system and user crontabs, while command bodies are redacted and job activity is not inferred.

Long-running `observe` sessions retain the most recent 30 days of snapshots automatically.

### Shutdown Impact
```
If you shut down db01:
  ✗ web01 fails immediately (depends directly)
  ✗ app02 fails immediately (depends directly)
  ⚠️  elasticsearch01 degrades (loses replication peer)
  
Cascade risk: MEDIUM (2 systems lose access, 1 degrades)
```

## Features

| Feature | Status |
|---------|--------|
| Network observation | ✅ Phase 1 |
| Process tracking | ✅ Phase 1 |
| Cron/timer detection | ✅ Phase 1 |
| Dependency inference | ✅ Phase 2 |
| Confidence scoring with evidence | ✅ Phase 2 |
| 7-day observation window | ✅ Phase 2 |
| Configuration scanning | ✅ Phase 3 |
| DNS resolution | ✅ Phase 3 |
| ASCII dependency graphs | ✅ Phase 3 |
| Interactive HTML dashboard | ✅ Phase 4 |
| **Reverse dependency detection** | ✅ Phase 5 |
| **Infrastructure-wide mapping** | ✅ Phase 5 |
| Pre-flight safety checks | ✅ Phase 7 |
| Cascade failure analysis | ✅ Phase 5 |

## Commands

```bash
# Core observation
screamless snapshot                     # Single observation now
screamless observe --duration 7d        # 7-day observation (default)

# Analysis & Reports
screamless report                       # Text report
screamless report --format json         # Machine-readable output
screamless decommission-check           # Readiness assessment
screamless dashboard --output rep.html  # Interactive HTML

# Safety & Planning
screamless preflight --server db01 --operation restart    # Is restart safe?
screamless infrastructure --servers db01,web01,cache01    # Map all dependencies
```

## Use Cases

### 1. **Safe Decommissioning**
```bash
screamless observe --duration 7d
screamless decommission-check
# Output: "READY (85%). Observed no external dependencies."
```

### 2. **Before a Deployment**
```bash
screamless preflight --server nginx01 --operation update
# Output: "✅ SAFE. No dependent servers detected."
```

### 3. **Incident Response**
```bash
# Database went down — what was depending on it?
screamless infrastructure --servers prod-db01
# Shows: which apps lost connectivity, which degraded
```

### 4. **Infrastructure Planning**
```bash
screamless infrastructure --servers web01,web02,web03,db01,cache01
# Shows: single points of failure, consolidation opportunities
```

### 5. **Compliance/Audit**
```bash
screamless dashboard --output compliance-report.html
# Shareable, timestamped, evidence-backed dependency map
```

## How It Works

### Outbound Detection
- Polls TCP and UDP sockets through `ss` with a `netstat` fallback
- Correlates with running processes
- Finds config file references
- Assigns confidence based on evidence

Polling is a fallback observation method and can miss very short-lived connections or datagrams. Event-driven eBPF, conntrack, and service-mesh telemetry are not currently included.

### Inbound Detection
Screamless derives inbound dependencies by reversing observed outbound edges from the other hosts in the database. If `web01` is observed connecting to `db01:3306`, the topology records `web01` as a dependent of `db01`. Local DNS records, access-log IPs, Git remotes, SSH configuration, and mount configuration are not treated as server-to-server inbound dependencies.

Each detection method provides evidence. More evidence = higher confidence.

### Impact Analysis
- **Cascade detection**: "If I shut down, these servers lose access, those degrade"
- **Single point of failure**: "13 systems have no alternative if I'm gone"
- **Cluster mapping**: "These 8 services always work together"

## The Legendary Advantage

Screamless is **legendary** because:

✅ **Solves the real problem**: Not "detect services," but "what breaks if I change this?"

✅ **Evidence-based**: Every claim shows WHY we think it's true

✅ **Fast**: 7-day observation, not months of documentation

✅ **Safe**: Color-coded confidence, clear risk levels

✅ **Shareable**: Single HTML file, works offline

✅ **Truthful**: Finds actual dependencies, not guesses

## Installation

```bash
# Clone
git clone <repo>
cd screamless

# Build
cargo build --release

# Deploy (literally one binary)
scp target/release/screamless root@server:/usr/local/bin/
ssh root@server screamless observe --duration 7d
ssh root@server screamless report
```

## Why It Matters

In 2026, most infrastructure is undocumented. Screamless fixes that by being **observational, not declarative**.

- No config files to maintain
- Collectors inspect the local host; multi-server graphs require snapshots from each host to be present in the analyzed database
- No learning curve
- Configuration evidence is matched by hostname/IP and compatible port, not by port alone

A single command gives you the truth about your servers.

## Project Status

**Production-ready.** All 5 phases complete.

- Phase 1-4: Foundational observability and dashboards
- Phase 5: Reverse dependency inference (the legendary feature)
- Phases 6-7: Infrastructure mapping and automation

## Example Output

```
╭──────────────────────────────────────────╮
│  SCREAMLESS DECOMMISSION REPORT          │
╰──────────────────────────────────────────╯

Server: legacy-web-03
Observation: 7 days (168 snapshots)
Readiness: 92%

✓ READY FOR DECOMMISSION

OUTBOUND DEPENDENCIES:
  None detected

INBOUND DEPENDENCIES:
  None detected (no other servers depend on this)

RISKS:
  ⚠️ 47 scheduled jobs configured
  ℹ️ Old PHP 5.6 observed during the window

RECOMMENDATION:
  Safe to decommission. Notify DNS team to remove DNS entries.
  Keep backup of config for 30 days.
```

## License

MIT

---

**Built by sysadmins, for sysadmins who are tired of the scream test.**
