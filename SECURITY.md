# Security Policy

Screamless is an experimental observation tool, not a complete security or
change-safety control. Do not use an empty report or a high readiness score as
the sole approval for decommissioning, restart, or deployment.

Reports can contain infrastructure names, addresses, process names, and
configuration evidence. Treat generated databases and HTML reports as
sensitive operational data. Review them before sharing and store them with
appropriate filesystem permissions.

The collector is local and polling-based. Missing privileges, failed probes,
short-lived traffic, remote hosts, containers, and network namespaces can
produce incomplete evidence. An incomplete probe is UNKNOWN, not evidence that
no dependency exists.

To report a security issue, open a private GitHub security report or contact
the repository maintainers before public disclosure:

https://github.com/cyberducttape/ScreemLess/security
