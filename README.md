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

## Install

```sh
npm install -g @agentlaunchopsai/compose-risk-guard
```

## Use

```sh
compose-risk-guard .
compose-risk-guard . --json
compose-risk-guard . --sarif
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

## License

MIT
