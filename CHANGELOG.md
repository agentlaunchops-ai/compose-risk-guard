# Changelog

## Unreleased

- Add `CRG075` to flag host messaging app data bind-mounted into Compose
  services.
- Add `CRG074` to flag host calendar or contact data bind-mounted into Compose
  services.
- Add `CRG073` to flag host artifact signing credentials bind-mounted into
  Compose services.
- Add `CRG072` to flag host VPN client profiles or state bind-mounted into
  Compose services.
- Add `CRG071` to flag host mobile app signing credentials bind-mounted into
  Compose services.
- Add `CRG070` to flag host language runtime package caches bind-mounted into
  Compose services.
- Add `CRG069` to flag host remote access credentials bind-mounted into Compose
  services.
- Add `CRG068` to flag host private sync tool identity data bind-mounted into
  Compose services.
- Add `CRG067` to flag host browser automation session state bind-mounted into
  Compose services.
- Add `CRG066` to flag host hardware authenticator or passkey state bind-mounted
  into Compose services.
- Add `CRG065` to flag host OS keychain or keyring data bind-mounted into
  Compose services.
- Add `CRG064` to flag host notes or knowledge-base data bind-mounted into
  Compose services.
- Add `CRG063` to flag host terminal emulator state bind-mounted into Compose
  services.
- Add `CRG062` to flag host editor or IDE state bind-mounted into Compose
  services.
- Add `CRG061` to flag shell startup files bind-mounted into Compose services.
- Add `CRG060` to flag secret manager CLI credentials bind-mounted into
  Compose services.
- Add `CRG059` to flag certificate authority or TLS private key material
  bind-mounted into Compose services.
- Add `CRG058` to flag host CI/CD service credentials bind-mounted into Compose
  services.
- Add `CRG057` to flag host API client credentials bind-mounted into Compose
  services.
- Add `CRG056` to flag local LLM runtime data bind-mounted into Compose
  services.
- Add `CRG055` to flag password manager vaults or credentials bind-mounted
  into Compose services.
- Add `CRG054` to flag email client credentials bind-mounted into Compose
  services.
- Add `CRG053` to flag collaboration app credentials bind-mounted into Compose
  services.
- Add `CRG052` to flag payment processor credentials bind-mounted into
  Compose services.
- Add `CRG051` to flag observability tool credentials bind-mounted into
  Compose services.
- Add `CRG050` to flag deployment platform credentials bind-mounted into
  Compose services.
- Add `CRG049` to flag tunnel and proxy credentials bind-mounted into Compose
  services.
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
