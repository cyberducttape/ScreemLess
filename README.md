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

**Experimental dependency archaeology.** During a passive observation window, Screamless can show:

1. **What this server connects to** (outbound dependencies)
2. **What connects to this server** (inbound dependencies) 
3. **Evidence and confidence for each** (with data-quality warnings)
4. **Impact if you shut it down** (cascade analysis)
5. **High-fan-in services** (redundancy is not inferred)

## Quick Start

```bash
# Install the published release (no Rust toolchain required)
curl -fsSL https://raw.githubusercontent.com/cyberducttape/ScreemLess/v1.1.0/install.sh | bash

# Or download a versioned artifact from GitHub Releases
# screamless-1.1.0-linux-amd64.tar.gz

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
  api.vendor.com:443  61% confidence (2 socket observations; config evidence is supporting context)
```

### Inbound Dependencies  
```
These servers depend on THIS one:
  web01        95% confidence (observed outbound connections to this server)
  monitor01    92% confidence (observed outbound connections to this server in the shared database)
```

Process activity counts snapshots in which a process was observed; it does not claim to count process executions. Cron discovery parses schedules from system and user crontabs, while command bodies are redacted and job activity is not inferred.

Long-running `observe` sessions retain the most recent 30 days of snapshots automatically.

### Storage architecture

The JSON snapshot in `snapshots.data` is the canonical audit/provenance record and
is the source used by analysis. Legacy normalized relationship tables are retained
for compatibility with older databases, but new snapshots are not duplicated into
those tables. This keeps collection to one serialization and one database write
while preserving the complete evidence needed for future analysis.

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
| Interactive HTML dashboard | ✅ Phase 4 (local data only) |
| **Reverse dependency detection** | ✅ Phase 5 |
| **Snapshot-database mapping** | ✅ Phase 5 (requires local data from each host) |
| Pre-flight safety checks | ✅ Phase 7 |
| Cascade failure analysis | ✅ Phase 5 |
| Website and infrastructure inventory | ✅ Config-backed, evidence-labeled |

The inventory shown in JSON reports and the dashboard includes configured
virtual hosts, active/inactive listener status, document roots, observed users,
recognized application processes, inferred database/storage connections, and
load-balancer candidates backed by upstream/proxy configuration. Reverse-proxy
configuration is parsed for Nginx, Apache, HAProxy, Traefik, and Caddy. Inbound site
traffic is reported as observed established-socket connections; it is not HTTP
request or visitor analytics.

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
# Output: a readiness assessment, or UNKNOWN when required evidence is incomplete
```

### 2. **Before a Deployment**
```bash
screamless preflight --server nginx01 --operation update
# Output: a safety result; incomplete evidence is non-zero and must be reviewed
```

Automation exit codes are consistent across preflight and decommission checks:

- `0`: evidence supports the operation
- `1`: internal failure
- `2`: evidence identifies an operation-specific blocker
- `3`: invalid invocation
- `4`: insufficient or unknown evidence

Operation policy is specific to the requested action. A listening service is
relevant to decommissioning but is not, by itself, evidence that a restart is unsafe.

### 3. **Incident Response**
```bash
# Database went down — what was depending on it?
screamless infrastructure --servers prod-db01
# Shows: which apps lost connectivity, which degraded
```

### 4. **Infrastructure Planning**
```bash
screamless infrastructure --servers web01,web02,web03,db01,cache01
# Shows: observed relationships and high-fan-in services
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

Each relationship should be read by evidence class:

- **OBSERVED**: a socket observation from a collector. This is the strongest current evidence, but polling can miss short-lived traffic.
- **DECLARED**: a configuration reference that matches a host or address and compatible port. It is supporting evidence, not proof of traffic.
- **INFERRED**: a heuristic hint such as log, DNS, or access information. Current inbound topology is deliberately based on reversed observed edges instead.
- **UNKNOWN**: a probe failed, permissions were insufficient, or the observation window was inadequate. Unknown is not equivalent to no dependency.

Confidence is a summary of available evidence and data quality; it is not a probability that a dependency exists.

### Impact Analysis
- **Cascade detection**: "If I shut down, these servers lose access, those degrade"
- **High-fan-in candidates**: highlights observed inbound concentration; redundancy, VIPs, replication, and alternate paths are not verified
- **Cluster mapping**: "These 8 services always work together"

## What This Prototype Does Well

Screamless is useful when treated as an evidence collector:

✅ **Solves the real problem**: Not "detect services," but "what breaks if I change this?"

✅ **Evidence-based**: Every claim shows WHY we think it's true

✅ **Fast**: a lightweight polling collector, not a complete network tap

✅ **Safe**: Color-coded confidence, clear risk levels

✅ **Shareable**: Single HTML file with no CDN runtime dependency

✅ **Conservative**: separates observed network evidence from supporting hints

## Installation

```bash
# Source build (development only)
git clone --branch v1.1.0 https://github.com/cyberducttape/ScreemLess
cd ScreemLess

# Build
cargo build --release

# Deploy the binary to the host being observed
scp target/release/screamless root@server:/usr/local/bin/
ssh root@server screamless observe --duration 7d
ssh root@server screamless report
```

Published releases include:

- `screamless_1.1.0_amd64.deb`
- `screamless-1.1.0-1.x86_64.rpm`
- `screamless-1.1.0-linux-amd64.tar.gz`
- `screamless-1.1.0-source.tar.gz` (tracked source only; no `.git/`)
- `SHA256SUMS`, `SBOM.spdx.json`, and Cosign signature material

The package/installer can enable the collector with:

```bash
sudo systemctl enable --now screamless-agent
```

## Why It Matters

In 2026, most infrastructure is undocumented. Screamless provides local observational evidence, but it does not replace an event-driven network sensor or a central multi-host ingest service.

- No config files to maintain
- Collectors inspect only the local host; the infrastructure command cannot collect remote hosts and requires their snapshots to already be in the same database
- Polling can miss short-lived TCP/UDP activity
- Configuration evidence is matched by hostname/IP and compatible port, not by port alone

A report is a starting point for validation, not proof that no dependency exists.

## Project Status

**Prototype / experimental.** The collection and analysis paths are useful for investigation, but this is not a production safety oracle.

- Phase 1-4: Foundational observability and dashboards
- Phase 5: Reverse observed outbound edges for inbound reporting
- Phases 6-7: Infrastructure mapping and automation

## Example Output

```
╭──────────────────────────────────────────╮
│  SCREAMLESS DECOMMISSION REPORT          │
╰──────────────────────────────────────────╯

Server: legacy-web-03
Observation: 7 days (168 snapshots)
Readiness: 92%

  ? INSUFFICIENT EVIDENCE

OUTBOUND DEPENDENCIES:
  None detected

INBOUND DEPENDENCIES:
  None observed (this does not prove that no other servers depend on this)

RISKS:
  ⚠️ 47 scheduled jobs configured
  ℹ️ Old PHP 5.6 observed during the window

RECOMMENDATION:
  Validate with service owners and independent telemetry before decommissioning.
  Keep a backup of configuration and evidence.
```

## Security and Contributing

See [SECURITY.md](SECURITY.md) for operational limitations and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance.

Pull requests are expected to pass formatting, Clippy with warnings denied,
all tests, and a locked release build. Generated databases and dashboards are
written with owner-only permissions and dashboard writes are atomic.

## License

MIT

---

**Built by sysadmins, for sysadmins who are tired of the scream test.**
