# Compose Risk Guard

Compose Risk Guard scans Docker Compose files for secret-like environment values
and host-access settings that are easy to miss in review.

It checks for:

- secret-looking `environment` entries with literal values
- secret-looking keys inside referenced env files
- secret-looking `build.args` entries with literal values
- `privileged: true`
- Docker socket bind mounts
- host namespace sharing through `network_mode`, `pid`, or `ipc`
- bind mounts of sensitive host paths
- unpinned or `latest` image tags
- high-risk Linux capabilities added through `cap_add`
- disabled container security profiles in `security_opt`
- sensitive service ports published on all interfaces
- services explicitly configured to run as root
- additional host namespace sharing through `cgroup`, `uts`, or `userns_mode`
- sensitive host devices exposed through `devices`
- host gateway mappings exposed through `extra_hosts`
- TLS certificate verification bypasses in service environment values
- high-risk kernel and networking settings in `sysctls`
- disabled container healthchecks
- disabled container logging
- container runtime socket bind mounts
- host SSH agent socket bind mounts
- capability additions without first dropping default capabilities
- services joining another service's network, PID, or IPC namespace
- services explicitly disabling a read-only root filesystem
- secret-looking service labels with literal values
- Docker clients pointed at insecure TCP daemons
- build contexts that escape the scanned project
- env files that escape the scanned project
- secret files that escape the scanned project
- config files that escape the scanned project
- host Docker client credential directories or files bind-mounted into services
- host cloud provider credential directories or files bind-mounted into services
- host Kubernetes credential directories or files bind-mounted into services
- host package manager credential files bind-mounted into services
- host build tool credential files bind-mounted into services
- dotenv credential files bind-mounted into services
- host shell or REPL history files bind-mounted into services
- host password stores or PGP secrets bind-mounted into services
- Terraform or OpenTofu state or credential files bind-mounted into services
- SOPS or age secret-management keys bind-mounted into services
- cryptocurrency wallet or chain keys bind-mounted into services
- host AI provider credential directories or files bind-mounted into services
- host browser profile data bind-mounted into services
- host database client credential files bind-mounted into services
- host backup or sync credential files bind-mounted into services
- host container registry credentials or certificate stores bind-mounted into services
- host tunnel or proxy credentials bind-mounted into services
- host deployment platform credentials bind-mounted into services
- host observability tool credentials bind-mounted into services
- host payment processor credentials bind-mounted into services
- host collaboration app credentials bind-mounted into services
- host email client credentials bind-mounted into services
- host password manager vaults or credentials bind-mounted into services
- host local LLM runtime data bind-mounted into services
- host API client credentials bind-mounted into services
- host CI/CD service credentials bind-mounted into services
- host certificate authority or TLS private key material bind-mounted into services
- host secret manager credentials bind-mounted into services
- host shell startup files bind-mounted into services
- host notes or knowledge-base data bind-mounted into services
- host terminal emulator state bind-mounted into services
- host OS keychain or keyring data bind-mounted into services
- host hardware authenticator or passkey state bind-mounted into services
- host browser automation session state bind-mounted into services
- host private sync tool identity data bind-mounted into services
- host remote access credentials bind-mounted into services
- host language runtime package caches bind-mounted into services
- host mobile app signing credentials bind-mounted into services
- host VPN client profiles or state bind-mounted into services
- host artifact signing credentials bind-mounted into services
- host calendar or contact data bind-mounted into services
- host messaging app data bind-mounted into services
- host credential agent sockets bind-mounted into services
- host tax or accounting app data bind-mounted into services
- host photo library data bind-mounted into services
- host music or media library data bind-mounted into services
- host Git or SSH credential files bind-mounted into services
- services joining another container's network, PID, or IPC namespace

## Install

```sh
npm install -g @agentlaunchopsai/compose-risk-guard
```

## Use

```sh
compose-risk-guard .
compose-risk-guard . --json
compose-risk-guard . --sarif
compose-risk-guard . --github
compose-risk-guard . --no-fail
npx @agentlaunchopsai/compose-risk-guard .
```

By default it scans common Compose filenames such as `compose.yml`,
`compose.yaml`, `docker-compose.yml`, and `docker-compose.yaml`.

## CI

```yaml
name: compose-risk-guard
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx -y @agentlaunchopsai/compose-risk-guard . --github
```

To upload the same findings to GitHub code scanning, emit SARIF instead:

```yaml
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx -y @agentlaunchopsai/compose-risk-guard . --sarif --no-fail > compose-risk-guard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: compose-risk-guard.sarif
```

## Rules

| Rule | Check |
| --- | --- |
| `CRG001` | Secret-like environment variable has a literal value |
| `CRG002` | Referenced env file contains a secret-like literal |
| `CRG003` | Service runs with `privileged: true` |
| `CRG004` | Service bind-mounts the Docker socket |
| `CRG005` | Service shares a host namespace |
| `CRG006` | Service bind-mounts a sensitive host path |
| `CRG007` | Service image uses `latest` or has no explicit tag/digest |
| `CRG008` | Secret-like build argument has a literal value |
| `CRG009` | Service adds a high-risk Linux capability |
| `CRG010` | Service disables a container security profile |
| `CRG011` | Service publishes a sensitive port on all interfaces |
| `CRG012` | Service explicitly runs as root |
| `CRG013` | Service shares an additional host namespace |
| `CRG014` | Service maps a sensitive host device |
| `CRG015` | Service maps a hostname to the Docker host gateway |
| `CRG016` | Service disables TLS certificate verification |
| `CRG017` | Service sets a high-risk kernel sysctl |
| `CRG018` | Service disables its container healthcheck |
| `CRG019` | Service disables container logging |
| `CRG020` | Service bind-mounts a container runtime socket |
| `CRG021` | Service bind-mounts a host SSH agent socket |
| `CRG022` | Service adds capabilities without dropping defaults first |
| `CRG023` | Service joins another service namespace |
| `CRG024` | Service explicitly disables a read-only root filesystem |
| `CRG025` | Service label contains a secret-like literal |
| `CRG026` | Service points Docker clients at an insecure TCP daemon |
| `CRG027` | Service build context escapes the scanned project |
| `CRG028` | Service `env_file` escapes the scanned project |
| `CRG029` | Compose secret `file` escapes the scanned project |
| `CRG030` | Service bind-mounts host Docker client credentials |
| `CRG031` | Service bind-mounts host cloud provider credentials |
| `CRG032` | Service bind-mounts host Kubernetes credentials |
| `CRG033` | Service bind-mounts host package manager credentials |
| `CRG034` | Service bind-mounts host Git or SSH credentials |
| `CRG035` | Service joins another container namespace |
| `CRG036` | Compose config `file` escapes the scanned project |
| `CRG037` | Service bind-mounts host build tool credentials |
| `CRG038` | Service bind-mounts dotenv credential files |
| `CRG039` | Service bind-mounts host shell or REPL history files |
| `CRG040` | Service bind-mounts host password store or PGP secrets |
| `CRG041` | Service bind-mounts Terraform or OpenTofu state or credentials |
| `CRG042` | Service bind-mounts SOPS or age secret-management keys |
| `CRG043` | Service bind-mounts cryptocurrency wallet or chain keys |
| `CRG044` | Service bind-mounts host AI provider credentials |
| `CRG045` | Service bind-mounts host browser profile data |
| `CRG046` | Service bind-mounts host database client credentials |
| `CRG047` | Service bind-mounts host backup or sync credentials |
| `CRG048` | Service bind-mounts host container registry credentials or certificates |
| `CRG049` | Service bind-mounts host tunnel or proxy credentials |
| `CRG050` | Service bind-mounts host deployment platform credentials |
| `CRG051` | Service bind-mounts host observability tool credentials |
| `CRG052` | Service bind-mounts host payment processor credentials |
| `CRG053` | Service bind-mounts host collaboration app credentials |
| `CRG054` | Service bind-mounts host email client credentials |
| `CRG055` | Service bind-mounts host password manager vaults or credentials |
| `CRG056` | Service bind-mounts host local LLM runtime data |
| `CRG057` | Service bind-mounts host API client credentials |
| `CRG058` | Service bind-mounts host CI/CD service credentials |
| `CRG059` | Service bind-mounts host certificate authority or TLS private key material |
| `CRG060` | Service bind-mounts host secret manager credentials |
| `CRG061` | Service bind-mounts host shell startup files |
| `CRG062` | Service bind-mounts host editor or IDE state |
| `CRG063` | Service bind-mounts host terminal emulator state |
| `CRG064` | Service bind-mounts host notes or knowledge-base data |
| `CRG065` | Service bind-mounts host OS keychain or keyring data |
| `CRG066` | Service bind-mounts host hardware authenticator or passkey state |
| `CRG067` | Service bind-mounts host browser automation session state |
| `CRG068` | Service bind-mounts host private sync tool identity data |
| `CRG069` | Service bind-mounts host remote access credentials |
| `CRG070` | Service bind-mounts host language runtime package caches |
| `CRG071` | Service bind-mounts host mobile app signing credentials |
| `CRG072` | Service bind-mounts host VPN client profiles or state |
| `CRG073` | Service bind-mounts host artifact signing credentials |
| `CRG074` | Service bind-mounts host calendar or contact data |
| `CRG075` | Service bind-mounts host messaging app data |
| `CRG076` | Service bind-mounts a host credential agent socket |
| `CRG077` | Service bind-mounts host tax or accounting app data |
| `CRG078` | Service bind-mounts host photo library data |
| `CRG079` | Service bind-mounts host music or media library data |

## License

MIT
