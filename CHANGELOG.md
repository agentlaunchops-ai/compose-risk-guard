# Changelog

## Unreleased

- Add `CRG048` to flag host container registry credentials and certificate
  stores bind-mounted into Compose services.
- Add `CRG047` to flag host backup and sync credentials bind-mounted into
  Compose services.
- Add `CRG046` to flag host database client credentials bind-mounted into
  Compose services.
- Add `CRG045` to flag host browser profile data bind-mounted into Compose
  services.
- Add `CRG044` to flag host AI provider credentials bind-mounted into Compose
  services.
- Add `CRG043` to flag cryptocurrency wallet and chain keys bind-mounted into
  Compose services.
- Add `CRG042` to flag SOPS and age secret-management keys bind-mounted into
  Compose services.
- Add `CRG041` to flag Terraform and OpenTofu state or credential files
  bind-mounted into Compose services.
- Add `CRG040` to flag host password stores and PGP secrets bind-mounted into
  Compose services.
- Add `CRG039` to flag host shell and REPL history files bind-mounted into
  Compose services.
- Add `CRG038` to flag dotenv credential files bind-mounted into Compose
  services.
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
