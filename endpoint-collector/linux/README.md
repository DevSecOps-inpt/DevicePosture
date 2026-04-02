# Linux Collector Placeholder

The Windows-native endpoint agent is currently implemented in PowerShell so it can run on a standard Windows installation without adding Python or other dependencies.

This folder is reserved for a future Linux collector. When that version is added, it should follow the same payload contract and config-driven plugin layout:

- periodic collection loop
- enabled collectors list in config
- normalized telemetry JSON
- POST to `telemetry-api`
- extension points for additional Linux-specific checks
