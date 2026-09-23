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

## What it collects (Phase 1)

- **Listening services**: processes listening on ports
- **Network connections**: established TCP connections to remote services
- **Processes**: running processes with their command lines
- **Cron jobs**: scheduled jobs in `/etc/cron.*`
- **Systemd timers**: systemd timer units

## Project Status

**Phase 1**: Basic observability infrastructure. Single snapshots and reports.

**Phase 2** (planned): Decommission mode with confidence scoring.

**Phase 3** (planned): Interactive graph visualization with evidence.

## Design principles

- **Single binary**: `screamless` is one self-contained executable. No services, no account, no dashboard.
- **Local database**: SQLite for minimal dependencies.
- **Evidence, not magic**: Every finding cites what we actually observed.
- **Observable infrastructure**: Emphasis on /proc, systemd, standard Linux tools.

## Commands

```
screamless snapshot              Take a single snapshot now
screamless report [--hostname X] Generate a report from observations
screamless decommission-check    Check if safe to decommission
screamless observe --duration X  Observe for X time (e.g. 24h, 1d)
```

## Database

Snapshots are stored in a local SQLite database (default: `./screamless.db`). Pass `--db <path>` to use a different location.

## Requirements

- Linux kernel (tested on 5.x+)
- `systemctl` for timer observation
- `ss` or `netstat` for network inspection
- Rust 1.70+ to build

## License

TBD
