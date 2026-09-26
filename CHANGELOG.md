# Changelog

## [1.1.0] - 2026-09-26

Screamless 1.1.0 adds production-oriented evidence, inventory, and release
hardening while keeping the collector conservative about what it can prove.

### Added

- Host identity inventory and fleet-scale dependency graph analysis
- Reverse-proxy and software-version inventory without executing workload binaries
- Observation coverage, configuration-scan audit data, and evidence-first dashboard
- Versioned infrastructure JSON output and documented automation exit codes
- Versioned release artifacts, checksums, SPDX SBOM, and systemd agent packaging

### Changed

- High-fan-in candidates no longer claim single-point-of-failure status
- Socket observations are no longer presented as connection-event counts
- Configuration discovery is recursive, bounded, comment-aware, and symlink-safe
- Installation uses signed/versioned release artifacts instead of tracking `master`
- CI validates the declared Rust 1.70 MSRV on a pinned Ubuntu 24.04 runner

## [1.0.0] - 2026-09-23

Screamless 1.0.0 is an experimental Linux dependency-observation prototype.
It is not a production safety oracle. This release focuses on making
available evidence explicit and preventing missing evidence from being
reported as proof of safety.

### Available

- Local process, TCP, and UDP socket snapshots using ss with a netstat fallback
- Normalized SQLite persistence with schema versioning and retention
- Configuration references with credential and query-string redaction
- System and user cron schedule discovery with redacted command bodies
- Systemd timer collection
- Outbound dependency analysis from observed local sockets
- Inbound reporting by reversing observed outbound edges from snapshots already
  present in the analyzed database
- Evidence-quality warnings and non-zero preflight results for unsafe,
  incomplete, or invalid requests
- Self-contained HTML reports with a native SVG dependency view and restrictive
  content security policy

### Important limitations

- Collection is local. There is no remote SSH collector, ingest API, or
  central agent protocol.
- Socket collection is periodic polling and can miss short-lived TCP/UDP
  activity. Event-driven eBPF, conntrack, and service-mesh telemetry are not
  included.
- Process attribution may be unavailable without sufficient privileges.
- Configuration and log-style hints are supporting evidence, not proof of a
  live dependency.
- An empty result must be interpreted together with probe status and
  observation coverage; it does not prove that no dependency exists.
- The dashboard is offline-capable, but the project does not provide a D3.js
  force-directed graph or a complete infrastructure-wide topology ingest
  workflow.

### Evidence vocabulary

- OBSERVED: a network edge seen by the collector.
- DECLARED: a matching configuration reference.
- INFERRED: a heuristic relationship suggested by secondary evidence.
- UNKNOWN: required evidence was unavailable, incomplete, or permission
  restricted.

### Distribution

- Corrected installation and documentation links for versioned releases of
  github.com/cyberducttape/ScreemLess.
- Added MIT license, Cargo metadata, and committed Cargo.lock.

Future work includes event-driven collection, multi-host ingest, richer
evidence-graph records, container/network-namespace support, and broader
fixture/CI coverage.
