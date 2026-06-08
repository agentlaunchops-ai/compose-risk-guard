# Changelog

## Unreleased

- Add `CRG026` to flag Docker clients pointed at insecure TCP daemons.
- Add `CRG025` to flag secret-like service labels with literal values.
- Add `CRG024` to flag services that explicitly set `read_only: false`.
- Add `CRG023` to flag services that join another service's network, PID, or IPC
  namespace.
- Add `CRG022` to flag services that add Linux capabilities without first
  dropping default capabilities with `cap_drop: [ALL]`.

## 1.0.0

- Initial release.
- Scan Compose files for secret-like environment values, env files, privileged
  services, Docker socket mounts, host namespace sharing, sensitive bind mounts,
  and unpinned image tags.
- Support text, JSON, SARIF, and advisory CI mode with `--no-fail`.
