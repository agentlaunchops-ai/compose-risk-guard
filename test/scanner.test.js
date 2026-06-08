import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { formatText, scanProject, toSarif } from '../src/scanner.js';

const cli = path.resolve('src/cli.js');

test('clean compose file has no findings', () => {
  const dir = fixture({
    'compose.yml': `
services:
  app:
    image: node:20
    environment:
      API_TOKEN: \${API_TOKEN}
      DB_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
secrets:
  db_password:
    file: ./db_password.txt
`
  });

  assert.deepEqual(scanProject(dir), []);
});

test('literal secret environment values are reported', () => {
  const dir = fixture({
    'docker-compose.yml': `
services:
  api:
    image: api:1.2.3
    environment:
      API_KEY: live-value
      SAFE_VALUE: visible
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG001');
  assert.match(findings[0].message, /API_KEY/);
});

test('referenced env files are scanned for secret literals', () => {
  const dir = fixture({
    'compose.yml': `
services:
  db:
    image: postgres:16
    env_file:
      - ./database.env
`,
    'database.env': 'POSTGRES_PASSWORD=plain-text\nVISIBLE=true\n'
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG002');
  assert.equal(path.basename(findings[0].filePath), 'database.env');
});

test('env files outside the scanned project are reported without reading them', () => {
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-risk-guard-outside-'));
  fs.writeFileSync(path.join(outsideDir, 'prod.env'), 'API_TOKEN=outside-secret\n');

  const dir = fixture({
    'services/compose.yml': `
services:
  api:
    image: api:1.0.0
    env_file:
      - ${path.join(outsideDir, 'prod.env')}
      - \${COMPOSE_ENV_FILE}
  worker:
    image: worker:1.0.0
    env_file:
      - ../worker.env
`,
    'worker.env': 'VISIBLE=true\n'
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG028');
  assert.match(findings[0].message, /api/);
  assert.match(findings[0].message, /prod\.env/);
});

test('secret files outside the scanned project are reported', () => {
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-risk-guard-secrets-'));
  fs.writeFileSync(path.join(outsideDir, 'prod.key'), 'secret\n');

  const dir = fixture({
    'compose/compose.yml': `
services:
  api:
    image: api:1.0.0
    secrets:
      - prod_key
      - local_key
      - env_key
secrets:
  prod_key:
    file: ${path.join(outsideDir, 'prod.key')}
  local_key:
    file: ../local.key
  env_key:
    file: \${COMPOSE_SECRET_FILE}
`,
    'local.key': 'local-secret\n'
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG029');
  assert.match(findings[0].message, /prod_key/);
  assert.match(findings[0].message, /prod\.key/);
});

test('config files outside the scanned project are reported', () => {
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-risk-guard-configs-'));
  fs.writeFileSync(path.join(outsideDir, 'nginx.conf'), 'server {}\n');

  const dir = fixture({
    'compose/compose.yml': `
services:
  web:
    image: nginx:1.27
    configs:
      - source: nginx_conf
        target: /etc/nginx/conf.d/default.conf
configs:
  nginx_conf:
    file: ${path.join(outsideDir, 'nginx.conf')}
  local_conf:
    file: ../local.conf
  env_conf:
    file: \${COMPOSE_CONFIG_FILE}
`,
    'local.conf': 'server {}\n'
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG036');
  assert.match(findings[0].message, /nginx_conf/);
  assert.match(findings[0].message, /nginx\.conf/);
});

test('literal secret build args are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.2.3
    build:
      context: .
      args:
        API_TOKEN: build-token
        PUBLIC_FLAG: enabled
  worker:
    image: worker:1.2.3
    build:
      context: .
      args:
        - CLIENT_SECRET=\${CLIENT_SECRET}
        - PRIVATE_KEY=plain-text
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG008', 'CRG008']
  );
  assert(findings.some((finding) => finding.message.includes('API_TOKEN')));
  assert(findings.some((finding) => finding.message.includes('PRIVATE_KEY')));
});

test('build contexts outside the scanned project are reported', () => {
  const dir = fixture({
    'services/compose.yml': `
services:
  broad:
    image: broad:1.0.0
    build:
      context: ../..
  remote:
    image: remote:1.0.0
    build: https://github.com/example/app.git
  local:
    image: local:1.0.0
    build:
      context: .
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG027');
  assert.match(findings[0].message, /broad/);
});

test('build contexts inside the scanned project are allowed from subdirectories', () => {
  const dir = fixture({
    'compose/compose.yml': `
services:
  api:
    image: api:1.0.0
    build:
      context: ..
`
  });

  assert.deepEqual(scanProject(dir), []);
});

test('host access risks are reported', () => {
  const dir = fixture({
    'compose.yaml': `
services:
  worker:
    image: worker:latest
    privileged: true
    network_mode: host
    pid: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc:ro
`
  });

  const ids = scanProject(dir).map((finding) => finding.ruleId).sort();
  assert.deepEqual(ids, ['CRG003', 'CRG004', 'CRG005', 'CRG005', 'CRG006', 'CRG007']);
});

test('container runtime socket bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  builder:
    image: builder:1.0.0
    volumes:
      - /run/docker.sock:/run/docker.sock
      - /run/containerd/containerd.sock:/run/containerd/containerd.sock
      - /tmp/app.sock:/tmp/app.sock
  podman:
    image: podman:1.0.0
    volumes:
      - type: bind
        source: /run/podman/podman.sock
        target: /run/podman/podman.sock
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG020', 'CRG020', 'CRG020']
  );
  assert(findings.some((finding) => finding.message.includes('/run/docker.sock')));
  assert(findings.some((finding) => finding.message.includes('/run/containerd/containerd.sock')));
  assert(findings.some((finding) => finding.message.includes('/run/podman/podman.sock')));
});

test('host SSH agent socket bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  deployer:
    image: deployer:1.0.0
    volumes:
      - \${SSH_AUTH_SOCK}:/ssh-agent
      - /tmp/ssh-AbCdEf/agent.1234:/tmp/agent.sock
      - /tmp/app.sock:/tmp/app.sock
  desktop:
    image: desktop:1.0.0
    volumes:
      - type: bind
        source: /run/host-services/ssh-auth.sock
        target: /ssh-agent
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG021', 'CRG021', 'CRG021']
  );
  assert(findings.some((finding) => finding.message.includes('SSH_AUTH_SOCK')));
  assert(findings.some((finding) => finding.message.includes('/tmp/ssh-AbCdEf/agent.1234')));
  assert(findings.some((finding) => finding.message.includes('/run/host-services/ssh-auth.sock')));
});

test('host Docker client credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  builder:
    image: builder:1.0.0
    volumes:
      - \${HOME}/.docker/config.json:/root/.docker/config.json:ro
      - /tmp/cache:/cache
  desktop:
    image: desktop:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.docker
        target: /host-docker
  linux:
    image: linux:1.0.0
    volumes:
      - /home/alice/.docker/config.json:/tmp/config.json:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG030', 'CRG030', 'CRG030']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.docker/config.json')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.docker')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.docker/config.json')));
});

test('host cloud provider credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  aws:
    image: aws:1.0.0
    volumes:
      - \${HOME}/.aws:/root/.aws:ro
      - /tmp/cache:/cache
  azure:
    image: azure:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.azure
        target: /root/.azure
  gcloud:
    image: gcloud:1.0.0
    volumes:
      - /home/alice/.config/gcloud/application_default_credentials.json:/tmp/gcloud.json:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG031', 'CRG031', 'CRG031']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.aws')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.azure')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/gcloud')));
});

test('host Kubernetes credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  kubectl:
    image: kubectl:1.0.0
    volumes:
      - \${HOME}/.kube/config:/root/.kube/config:ro
      - /tmp/cache:/cache
  linux:
    image: linux:1.0.0
    volumes:
      - /home/alice/.kube:/host-kube:ro
  desktop:
    image: desktop:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.kube/cache
        target: /root/.kube/cache
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG032', 'CRG032', 'CRG032']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.kube/config')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.kube')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.kube/cache')));
});

test('host package manager credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  node:
    image: node:20
    volumes:
      - \${HOME}/.npmrc:/root/.npmrc:ro
      - /tmp/cache:/cache
  python:
    image: python:3.12
    volumes:
      - /home/alice/.pypirc:/tmp/pypirc:ro
  ruby:
    image: ruby:3.3
    volumes:
      - type: bind
        source: /Users/alice/.gem/credentials
        target: /root/.gem/credentials
  rust:
    image: rust:1.85
    volumes:
      - ~/.cargo/credentials:/root/.cargo/credentials:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG033', 'CRG033', 'CRG033', 'CRG033']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.npmrc')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.pypirc')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.gem/credentials')));
  assert(findings.some((finding) => finding.message.includes('~/.cargo/credentials')));
});

test('host build tool credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  maven:
    image: maven:3.9.9
    volumes:
      - \${HOME}/.m2/settings.xml:/root/.m2/settings.xml:ro
      - /tmp/cache:/cache
  gradle:
    image: gradle:8.14
    volumes:
      - /home/alice/.gradle/gradle.properties:/home/gradle/.gradle/gradle.properties:ro
  nuget:
    image: mcr.microsoft.com/dotnet/sdk:9.0
    volumes:
      - type: bind
        source: /Users/alice/.nuget/NuGet/NuGet.Config
        target: /root/.nuget/NuGet/NuGet.Config
  composer:
    image: composer:2.8
    volumes:
      - ~/.composer/auth.json:/tmp/auth.json:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG037', 'CRG037', 'CRG037', 'CRG037']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.m2/settings.xml')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.gradle/gradle.properties')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.nuget/NuGet/NuGet.Config')));
  assert(findings.some((finding) => finding.message.includes('~/.composer/auth.json')));
});

test('dotenv credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    volumes:
      - ./.env:/app/.env:ro
      - /tmp/cache:/cache
  worker:
    image: worker:1.0.0
    volumes:
      - \${HOME}/.env.production:/run/secrets/env:ro
  shell:
    image: shell:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.envrc
        target: /root/.envrc
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG038', 'CRG038', 'CRG038']
  );
  assert(findings.some((finding) => finding.message.includes('./.env')));
  assert(findings.some((finding) => finding.message.includes('${HOME}/.env.production')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.envrc')));
});

test('host shell and REPL history bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  shell:
    image: shell:1.0.0
    volumes:
      - \${HOME}/.bash_history:/root/.bash_history:ro
      - /tmp/cache:/cache
  db:
    image: postgres:16
    volumes:
      - /home/alice/.psql_history:/tmp/psql_history:ro
  node:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/.node_repl_history
        target: /root/.node_repl_history
  zsh:
    image: zsh:1.0.0
    volumes:
      - ~/.zsh_history:/tmp/zsh_history:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG039', 'CRG039', 'CRG039', 'CRG039']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.bash_history')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.psql_history')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.node_repl_history')));
  assert(findings.some((finding) => finding.message.includes('~/.zsh_history')));
});

test('host password stores and PGP secrets bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  pass:
    image: alpine:3.22
    volumes:
      - \${HOME}/.password-store:/root/.password-store:ro
      - /tmp/cache:/cache
  gpg:
    image: debian:12
    volumes:
      - /home/alice/.gnupg:/root/.gnupg:ro
  op:
    image: 1password/op:2.31.1
    volumes:
      - type: bind
        source: /Users/alice/.config/1Password
        target: /root/.config/1Password
  gopass:
    image: gopasspw/gopass:1.15.15
    volumes:
      - ~/.config/gopass:/root/.config/gopass:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG040', 'CRG040', 'CRG040', 'CRG040']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.password-store')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.gnupg')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/1Password')));
  assert(findings.some((finding) => finding.message.includes('~/.config/gopass')));
});

test('Terraform and OpenTofu state or credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  terraform:
    image: hashicorp/terraform:1.12.1
    volumes:
      - \${HOME}/.terraform.d/credentials.tfrc.json:/root/.terraform.d/credentials.tfrc.json:ro
      - ./terraform.tfstate:/workspace/terraform.tfstate:ro
      - /tmp/cache:/cache
  tofu:
    image: ghcr.io/opentofu/opentofu:1.10.0
    volumes:
      - type: bind
        source: /Users/alice/.tofu.d/credentials.tfrc.json
        target: /root/.tofu.d/credentials.tfrc.json
  backup:
    image: alpine:3.22
    volumes:
      - /home/alice/prod.tfstate.backup:/tmp/prod.tfstate.backup:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG041', 'CRG041', 'CRG041', 'CRG041']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.terraform.d/credentials.tfrc.json')));
  assert(findings.some((finding) => finding.message.includes('./terraform.tfstate')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.tofu.d/credentials.tfrc.json')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/prod.tfstate.backup')));
});

test('SOPS and age secret-management key bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  sops:
    image: mozilla/sops:v3.10.2
    volumes:
      - \${HOME}/.config/sops/age/keys.txt:/root/.config/sops/age/keys.txt:ro
      - /tmp/cache:/cache
  age:
    image: alpine:3.22
    volumes:
      - /home/alice/.config/age/keys.txt:/run/age-keys.txt:ro
  legacy:
    image: alpine:3.22
    volumes:
      - type: bind
        source: /Users/alice/.age-key.txt
        target: /root/.age-key.txt
  alt:
    image: alpine:3.22
    volumes:
      - ~/.sops/age/keys.txt:/root/.sops/age/keys.txt:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG042', 'CRG042', 'CRG042', 'CRG042']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/sops/age/keys.txt')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/age/keys.txt')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.age-key.txt')));
  assert(findings.some((finding) => finding.message.includes('~/.sops/age/keys.txt')));
});

test('host Git and SSH credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  git:
    image: alpine/git:2.49.0
    volumes:
      - \${HOME}/.gitconfig:/root/.gitconfig:ro
      - /home/alice/.git-credentials:/root/.git-credentials:ro
      - /tmp/cache:/cache
  gh:
    image: ghcr.io/cli/cli:2.74.0
    volumes:
      - type: bind
        source: /Users/alice/.config/gh
        target: /root/.config/gh
  ssh:
    image: openssh-client:1.0.0
    volumes:
      - ~/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG034', 'CRG034', 'CRG034', 'CRG034']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.gitconfig')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.git-credentials')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/gh')));
  assert(findings.some((finding) => finding.message.includes('~/.ssh/id_ed25519')));
});

test('high-risk added Linux capabilities are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  debugger:
    image: debugger:1.0.0
    cap_add:
      - SYS_PTRACE
      - CHOWN
  nettool:
    image: nettool:1.0.0
    cap_add: cap_net_admin
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG009', 'CRG022', 'CRG009', 'CRG022']
  );
  assert(findings.some((finding) => finding.message.includes('SYS_PTRACE')));
  assert(findings.some((finding) => finding.message.includes('NET_ADMIN')));
});

test('capability additions without dropping defaults are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  tuned:
    image: tuned:1.0.0
    cap_add:
      - NET_BIND_SERVICE
  hardened:
    image: hardened:1.0.0
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG022');
  assert.match(findings[0].message, /tuned/);
});

test('additional host namespace sharing is reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  kernelview:
    image: kernelview:1.0.0
    cgroup: host
    uts: host
  isolated:
    image: isolated:1.0.0
    userns_mode: private
  userns:
    image: userns:1.0.0
    userns_mode: host
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG013', 'CRG013', 'CRG013']
  );
  assert(findings.some((finding) => finding.message.includes('cgroup')));
  assert(findings.some((finding) => finding.message.includes('uts')));
  assert(findings.some((finding) => finding.message.includes('userns_mode')));
});

test('service namespace sharing is reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  sidecar:
    image: sidecar:1.0.0
    network_mode: service:api
  debugger:
    image: debugger:1.0.0
    pid: service:api
    ipc: service:api
  isolated:
    image: isolated:1.0.0
    network_mode: bridge
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG023', 'CRG023', 'CRG023']
  );
  assert(findings.some((finding) => finding.message.includes('network_mode: service:api')));
  assert(findings.some((finding) => finding.message.includes('pid: service:api')));
  assert(findings.some((finding) => finding.message.includes('ipc: service:api')));
});

test('container namespace sharing is reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  sniffer:
    image: sniffer:1.0.0
    network_mode: container:vpn
  debugger:
    image: debugger:1.0.0
    pid: container:api
    ipc: container:api
  isolated:
    image: isolated:1.0.0
    network_mode: service:api
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG035', 'CRG035', 'CRG035', 'CRG023']
  );
  assert(findings.some((finding) => finding.message.includes('network_mode: container:vpn')));
  assert(findings.some((finding) => finding.message.includes('pid: container:api')));
  assert(findings.some((finding) => finding.message.includes('ipc: container:api')));
});

test('sensitive host devices are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  vm:
    image: vm:1.0.0
    devices:
      - /dev/kvm:/dev/kvm
      - /dev/null:/dev/null
  graphics:
    image: graphics:1.0.0
    devices:
      - source: /dev/dri/renderD128
        target: /dev/dri/renderD128
  app:
    image: app:1.0.0
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG014', 'CRG014']
  );
  assert(findings.some((finding) => finding.message.includes('/dev/kvm')));
  assert(findings.some((finding) => finding.message.includes('/dev/dri/renderD128')));
});

test('host gateway mappings are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    extra_hosts:
      - "host.docker.internal:host-gateway"
      - "safe.internal:192.0.2.10"
  worker:
    image: worker:1.0.0
    extra_hosts:
      host.local: host-gateway
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG015', 'CRG015']
  );
  assert(findings.some((finding) => finding.message.includes('host.docker.internal')));
  assert(findings.some((finding) => finding.message.includes('host.local')));
});

test('TLS verification bypass environment values are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    environment:
      NODE_TLS_REJECT_UNAUTHORIZED: "0"
      GIT_SSL_NO_VERIFY: "true"
      CURL_SSL_NO_VERIFY: "false"
      PYTHONHTTPSVERIFY: "1"
  worker:
    image: worker:1.0.0
    env_file:
      - ./worker.env
`,
    'worker.env': 'AWS_SSL_VERIFY=false\nNODE_TLS_REJECT_UNAUTHORIZED=1\n'
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG016', 'CRG016', 'CRG016']
  );
  assert(findings.some((finding) => finding.message.includes('NODE_TLS_REJECT_UNAUTHORIZED')));
  assert(findings.some((finding) => finding.message.includes('GIT_SSL_NO_VERIFY')));
  assert(findings.some((finding) => finding.message.includes('AWS_SSL_VERIFY')));
});

test('high-risk sysctls are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  router:
    image: router:1.0.0
    sysctls:
      - net.ipv4.ip_forward=1
      - kernel.kptr_restrict=2
  bpf:
    image: bpf:1.0.0
    sysctls:
      kernel.unprivileged_bpf_disabled: "0"
      kernel.dmesg_restrict: "0"
  safe:
    image: safe:1.0.0
    sysctls:
      net.core.somaxconn: "1024"
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG017', 'CRG017', 'CRG017']
  );
  assert(findings.some((finding) => finding.message.includes('net.ipv4.ip_forward')));
  assert(findings.some((finding) => finding.message.includes('kernel.unprivileged_bpf_disabled')));
  assert(findings.some((finding) => finding.message.includes('kernel.dmesg_restrict')));
});

test('disabled healthchecks are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    healthcheck:
      disable: true
  worker:
    image: worker:1.0.0
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG018');
  assert.match(findings[0].message, /api/);
});

test('disabled container logging is reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    logging:
      driver: "none"
  worker:
    image: worker:1.0.0
    logging:
      driver: json-file
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG019');
  assert.match(findings[0].message, /api/);
});

test('explicitly writable root filesystems are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    read_only: false
  worker:
    image: worker:1.0.0
    read_only: true
  unset:
    image: unset:1.0.0
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CRG024');
  assert.match(findings[0].message, /api/);
});

test('literal secret label values are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    labels:
      com.example.api-token: plain-token
      com.example.visible: public
  worker:
    image: worker:1.0.0
    labels:
      - com.example.client_secret=\${CLIENT_SECRET}
      - com.example.password=plain-password
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG025', 'CRG025']
  );
  assert(findings.some((finding) => finding.message.includes('api-token')));
  assert(findings.some((finding) => finding.message.includes('password')));
});

test('insecure Docker daemon TCP endpoints are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    environment:
      DOCKER_HOST: tcp://docker-proxy:2375
  worker:
    image: worker:1.0.0
    environment:
      - DOCKER_HOST=tcp://docker-host:2375
  tls:
    image: tls:1.0.0
    environment:
      DOCKER_HOST: tcp://docker-host:2376
  socket:
    image: socket:1.0.0
    environment:
      DOCKER_HOST: unix:///var/run/docker.sock
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG026', 'CRG026']
  );
  assert(findings.some((finding) => finding.message.includes('api')));
  assert(findings.some((finding) => finding.message.includes('worker')));
});

test('disabled container security profiles are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  apparmorless:
    image: app:1.0.0
    security_opt:
      - apparmor:unconfined
      - no-new-privileges:true
  unlabeled:
    image: unlabeled:1.0.0
    security_opt: label:disable
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG010', 'CRG010']
  );
  assert(findings.some((finding) => finding.message.includes('apparmor:unconfined')));
  assert(findings.some((finding) => finding.message.includes('label:disable')));
});

test('sensitive ports published on all interfaces are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  db:
    image: postgres:16
    ports:
      - "5432:5432"
      - "127.0.0.1:6379:6379"
  cache:
    image: redis:7
    ports:
      - target: 6379
        published: "6379"
        host_ip: 0.0.0.0
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG011', 'CRG011']
  );
  assert(findings.some((finding) => finding.message.includes('5432')));
  assert(findings.some((finding) => finding.message.includes('6379')));
});

test('services explicitly running as root are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  api:
    image: api:1.0.0
    user: root
  worker:
    image: worker:1.0.0
    user: "0:0"
  app:
    image: app:1.0.0
    user: "1000:1000"
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG012', 'CRG012']
  );
  assert(findings.some((finding) => finding.message.includes('api')));
  assert(findings.some((finding) => finding.message.includes('worker')));
});

test('images without explicit non-latest tag or digest are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  missing:
    image: redis
  latest:
    image: nginx:latest
  pinned:
    image: postgres:16
  digest:
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`
  });

  const messages = scanProject(dir).map((finding) => finding.message);
  assert.equal(messages.length, 2);
  assert(messages.some((message) => message.includes('redis')));
  assert(messages.some((message) => message.includes('nginx:latest')));
});

test('text and sarif output include rules and locations', () => {
  const dir = fixture({
    'compose.yml': `
services:
  app:
    image: app
`
  });
  const findings = scanProject(dir);
  assert.match(formatText(findings, dir), /compose.yml:3 CRG007/);
  const sarif = toSarif(findings, dir);
  assert.equal(sarif.runs[0].tool.driver.name, 'compose-risk-guard');
  assert.equal(sarif.runs[0].results[0].ruleId, 'CRG007');
});

test('cli exits 0 when clean and 1 when findings exist', () => {
  const clean = fixture({ 'compose.yml': 'services:\n  app:\n    image: app:1.0.0\n' });
  const risky = fixture({ 'compose.yml': 'services:\n  app:\n    image: app\n' });

  assert.equal(spawnSync(process.execPath, [cli, clean]).status, 0);
  assert.equal(spawnSync(process.execPath, [cli, risky]).status, 1);
});

test('cli --no-fail reports findings while exiting 0', () => {
  const dir = fixture({ 'compose.yml': 'services:\n  app:\n    image: app\n' });
  const result = spawnSync(process.execPath, [cli, dir, '--no-fail'], { encoding: 'utf8' });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /CRG007/);
});

test('cli can emit json and sarif', () => {
  const dir = fixture({ 'compose.yml': 'services:\n  app:\n    image: app\n' });
  const json = spawnSync(process.execPath, [cli, dir, '--json'], { encoding: 'utf8' });
  const sarif = spawnSync(process.execPath, [cli, dir, '--sarif'], { encoding: 'utf8' });

  assert.equal(JSON.parse(json.stdout)[0].ruleId, 'CRG007');
  assert.equal(JSON.parse(sarif.stdout).version, '2.1.0');
});

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-risk-guard-'));
  for (const [relative, content] of Object.entries(files)) {
    const filePath = path.join(dir, relative);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content.trimStart());
  }
  return dir;
}
