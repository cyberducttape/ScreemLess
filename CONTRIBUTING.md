# Contributing

Screamless is an experimental Linux dependency-observation project. Changes
that affect collection, evidence classification, readiness, or exit codes
should include tests and documentation describing the limits of the evidence.

Before opening a change:

- run cargo test --all-targets
- keep Cargo.lock committed
- avoid storing credentials, command-line secrets, or raw configuration URLs
- add parser fixtures for new ss/netstat formats
- preserve the distinction between OBSERVED, DECLARED, INFERRED, and UNKNOWN
- do not describe missing observations as proof of safety

Use the repository issue tracker for design discussion and bug reports:

https://github.com/cyberducttape/ScreemLess/issues
