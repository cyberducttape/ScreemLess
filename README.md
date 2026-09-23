# Screamless

**Automatic Linux dependency archaeology.**

The core question: *"What will break if I reboot, migrate, upgrade, or decommission this server?"*

Screamless answers that question by observing your Linux system and building a map of what it actually does — what services it runs, what it talks to, what schedules it follows.

## Quick Start

### Build

```bash
cargo build --release
```

### Take a snapshot

```bash
./target/release/screamless snapshot
```

This collects one observation of your system and stores it in a local SQLite database.

### Generate a report

```bash
./target/release/screamless report
```

### Check decommission readiness

```bash
./target/release/screamless decommission-check
```

Tells you whether the system is safe to shut down, with evidence.

### Observe for a period

```bash
./target/release/screamless observe --duration 24h --interval 1m
```

Collects observations every 1 minute for 24 hours.

## What it collects

- **Listening services**: processes listening on ports
- **Network connections**: established TCP connections to remote services
- **Processes**: running processes with their command lines
- **Cron jobs**: scheduled jobs in `/etc/cron.*`
- **Systemd timers**: systemd timer units

## What it analyzes

**Phase 2**: Dependency inference & confidence scoring
- **Dependency inference**: Aggregates observations to identify outbound dependencies with confidence scoring
- **Temporal pattern detection**: Flags processes seen only once in the observation window
- **Risk assessment**: Identifies blocking issues, warnings, and informational items
- **Decommission confidence**: Scores readiness on a 0-100 scale with evidence
- **7-day observation window**: Captures weekly patterns (cron jobs, backups, etc.)

**Phase 3**: Configuration scanning & visualization
- **Config file parsing**: Scans nginx configs, PHP-FPM, WordPress, app configs for hardcoded hostnames
- **Evidence trails**: Shows which config files mention a dependency
- **DNS resolution**: Resolves hostnames found in configs to IPs
- **ASCII graph visualization**: Dependency tree showing local server → remote services
- **Confidence scoring**: Network observations + config references = trustworthy decisions

## Project Status

**Phase 1**: ✅ Basic observability infrastructure
- Single snapshots and reports with process/service/cron/timer collection

**Phase 2**: ✅ Dependency inference and confidence scoring  
- Network observation aggregation, temporal pattern detection, 7-day window, risk assessment

**Phase 3**: ✅ Configuration scanning and visualization
- Nginx/PHP-FPM/app config parsing, DNS resolution, ASCII graphs with evidence

**Phase 3 Enhancements**: ✅ Improved config discovery
- Extended patterns for Django, Node.js, Ruby, etc.
- Actual config lines captured as evidence
- Better hostname/URL extraction

**Phase 4**: ✅ Interactive HTML dashboard
- Beautiful, self-contained HTML reports
- D3.js force-directed dependency graphs
- Color-coded readiness assessment
- No server or deployment needed

**Phase 5** (future): Reverse dependency inference, timeline view, Kubernetes support

## Design principles

- **Single binary**: `screamless` is one self-contained executable. No services, no account, no dashboard.
- **Local database**: SQLite for minimal dependencies.
- **Evidence, not magic**: Every finding cites what we actually observed.
- **Observable infrastructure**: Emphasis on /proc, systemd, standard Linux tools.

## Commands

```
screamless snapshot              Take a single snapshot now
screamless report [--hostname X] Generate a report from observations
screamless report --format json  Output JSON for automation
screamless decommission-check    Check if safe to decommission
screamless dashboard             Generate interactive HTML dashboard
screamless observe --duration 7d Observe for 7 days (default)
```

## Dashboard

Generate an interactive HTML report:
```bash
screamless dashboard --output report.html
```

Features:
- **Real-time readiness score**: Green (ready) / Orange (caution) / Red (not ready)
- **Interactive dependency graph**: D3.js visualization with drag & zoom
- **Dependency list**: Each with confidence score and source processes
- **Risk panel**: Identified issues and warnings
- **Statistics**: Total dependencies, high-confidence count
- **Self-contained**: Single HTML file, works offline, can be emailed

## Database

Snapshots are stored in a local SQLite database (default: `./screamless.db`). Pass `--db <path>` to use a different location.

## Requirements

- Linux kernel (tested on 5.x+)
- `systemctl` for timer observation
- `ss` or `netstat` for network inspection
- Rust 1.70+ to build

## License

TBD
