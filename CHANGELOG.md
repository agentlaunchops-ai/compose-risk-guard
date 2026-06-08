# Changelog

## Unreleased

- Add `CRG037` to flag host build tool credential files bind-mounted into
  Compose services.
- Add `CRG036` to flag Compose config `file` references that escape the scanned
  project.
- Add `CRG035` to flag services that join another container's network, PID, or
  IPC namespace.
- Add `CRG034` to flag host Git and SSH credential files or directories
  bind-mounted into Compose services.
- Add `CRG033` to flag host package manager credential files bind-mounted into
  Compose services.
- Add `CRG032` to flag host Kubernetes credential files or directories
  bind-mounted into Compose services.
- Add `CRG031` to flag host cloud provider credential files or directories
  bind-mounted into Compose services.
- Add `CRG030` to flag host Docker client credential files or directories
  bind-mounted into Compose services.
- Add `CRG029` to flag Compose secret `file` references that escape the scanned
  project.
- Add `CRG028` to flag service `env_file` references that escape the scanned
  project.
- Add `CRG027` to flag service build contexts that escape the scanned project.
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
