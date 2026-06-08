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

## License

MIT
