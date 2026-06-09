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

test('host credential agent socket bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  signer:
    image: signer:1.0.0
    volumes:
      - /run/user/1000/gnupg/S.gpg-agent:/run/gnupg/S.gpg-agent
      - /tmp/cache:/cache
  desktop:
    image: desktop:1.0.0
    volumes:
      - type: bind
        source: /run/user/1000/keyring/secrets
        target: /run/keyring/secrets
  dbus:
    image: dbus:1.0.0
    volumes:
      - /run/user/1000/bus:/run/user/1000/bus
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG076', 'CRG076', 'CRG076']
  );
  assert(findings.some((finding) => finding.message.includes('/run/user/1000/gnupg/S.gpg-agent')));
  assert(findings.some((finding) => finding.message.includes('/run/user/1000/keyring/secrets')));
  assert(findings.some((finding) => finding.message.includes('/run/user/1000/bus')));
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

test('cryptocurrency wallet and chain key bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  bitcoin:
    image: bitcoin:28
    volumes:
      - \${HOME}/.bitcoin/wallet.dat:/wallet.dat:ro
      - /tmp/cache:/cache
  solana:
    image: solana:1.18
    volumes:
      - /home/alice/.config/solana/id.json:/root/.config/solana/id.json:ro
  ethereum:
    image: geth:1.15
    volumes:
      - type: bind
        source: /Users/alice/.ethereum/keystore
        target: /root/.ethereum/keystore
  foundry:
    image: ghcr.io/foundry-rs/foundry:stable
    volumes:
      - ~/.foundry/keystores:/root/.foundry/keystores:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG043', 'CRG043', 'CRG043', 'CRG043']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.bitcoin/wallet.dat')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/solana/id.json')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.ethereum/keystore')));
  assert(findings.some((finding) => finding.message.includes('~/.foundry/keystores')));
});

test('host AI provider credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  openai:
    image: node:20
    volumes:
      - \${HOME}/.openai:/root/.openai:ro
      - /tmp/cache:/cache
  claude:
    image: node:20
    volumes:
      - /home/alice/.claude.json:/root/.claude.json:ro
  cursor:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/.config/Cursor
        target: /root/.config/Cursor
  gemini:
    image: node:20
    volumes:
      - ~/.gemini:/root/.gemini:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG044', 'CRG044', 'CRG044', 'CRG044']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.openai')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.claude.json')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/Cursor')));
  assert(findings.some((finding) => finding.message.includes('~/.gemini')));
});

test('host browser profile bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  chrome:
    image: playwright:1.52.0
    volumes:
      - \${HOME}/.config/google-chrome:/browser-profile:ro
      - /tmp/cache:/cache
  firefox:
    image: selenium:4.33.0
    volumes:
      - /home/alice/.mozilla/firefox:/profiles/firefox:ro
  brave:
    image: browser:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/BraveSoftware
        target: /profiles/brave
  edge:
    image: browser:1.0.0
    volumes:
      - ~/Library/Application Support/Microsoft Edge:/profiles/edge:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG045', 'CRG045', 'CRG045', 'CRG045']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/google-chrome')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.mozilla/firefox')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/BraveSoftware')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Application Support/Microsoft Edge')));
});

test('host database client credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  postgres:
    image: postgres:16
    volumes:
      - \${HOME}/.pgpass:/root/.pgpass:ro
      - /tmp/cache:/cache
  mysql:
    image: mysql:8.4
    volumes:
      - /home/alice/.my.cnf:/root/.my.cnf:ro
  mongo:
    image: mongo:8.0
    volumes:
      - type: bind
        source: /Users/alice/.mongorc.js
        target: /root/.mongorc.js
  duckdb:
    image: alpine:3.22
    volumes:
      - ~/.duckdbrc:/root/.duckdbrc:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG046', 'CRG046', 'CRG046', 'CRG046']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.pgpass')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.my.cnf')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.mongorc.js')));
  assert(findings.some((finding) => finding.message.includes('~/.duckdbrc')));
});

test('host backup and sync credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  rclone:
    image: rclone/rclone:1.70
    volumes:
      - \${HOME}/.config/rclone/rclone.conf:/config/rclone/rclone.conf:ro
      - /tmp/cache:/cache
  restic:
    image: restic/restic:0.18.0
    volumes:
      - /home/alice/.config/restic:/root/.config/restic:ro
  borg:
    image: borgbackup/borg:1.4.1
    volumes:
      - type: bind
        source: /Users/alice/.borg
        target: /root/.borg
  restic-home:
    image: restic/restic:0.18.0
    volumes:
      - ~/.restic:/root/.restic:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG047', 'CRG047', 'CRG047', 'CRG047']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/rclone/rclone.conf')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/restic')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.borg')));
  assert(findings.some((finding) => finding.message.includes('~/.restic')));
});

test('host container registry credentials and certificates bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  podman:
    image: quay.io/podman/stable:v5.5
    volumes:
      - \${HOME}/.config/containers/auth.json:/run/auth.json:ro
      - /tmp/cache:/cache
  skopeo:
    image: quay.io/skopeo/stable:v1.18
    volumes:
      - /home/alice/.config/containers/certs.d:/etc/containers/certs.d:ro
  registry:
    image: registry:2.8
    volumes:
      - type: bind
        source: /etc/docker/certs.d/private.registry
        target: /certs/private.registry
  buildah:
    image: quay.io/buildah/stable:v1.40
    volumes:
      - ~/.local/share/containers/auth.json:/run/user-auth.json:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG048', 'CRG048', 'CRG048', 'CRG048']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/containers/auth.json')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/containers/certs.d')));
  assert(findings.some((finding) => finding.message.includes('/etc/docker/certs.d/private.registry')));
  assert(findings.some((finding) => finding.message.includes('~/.local/share/containers/auth.json')));
});

test('host tunnel and proxy credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  ngrok:
    image: ngrok/ngrok:3
    volumes:
      - \${HOME}/.config/ngrok/ngrok.yml:/etc/ngrok.yml:ro
      - /tmp/cache:/cache
  cloudflared:
    image: cloudflare/cloudflared:2026.6.0
    volumes:
      - /home/alice/.cloudflared:/etc/cloudflared:ro
  tailscale:
    image: tailscale/tailscale:v1.84.3
    volumes:
      - type: bind
        source: /var/lib/tailscale
        target: /var/lib/tailscale
  zerotier:
    image: zerotier/zerotier:1.14.2
    volumes:
      - ~/.config/zerotier:/var/lib/zerotier-one:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG049', 'CRG049', 'CRG049', 'CRG049']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/ngrok/ngrok.yml')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.cloudflared')));
  assert(findings.some((finding) => finding.message.includes('/var/lib/tailscale')));
  assert(findings.some((finding) => finding.message.includes('~/.config/zerotier')));
});

test('host deployment platform credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  vercel:
    image: node:20
    volumes:
      - \${HOME}/.vercel:/root/.vercel:ro
      - /tmp/cache:/cache
  netlify:
    image: node:20
    volumes:
      - /home/alice/.netlify:/root/.netlify:ro
  render:
    image: render:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.render
        target: /root/.render
  fly:
    image: flyio/flyctl:0.3.152
    volumes:
      - ~/.config/fly:/root/.fly:ro
  railway:
    image: railway:1.0.0
    volumes:
      - /root/.railway:/root/.railway:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG050', 'CRG050', 'CRG050', 'CRG050', 'CRG050']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.vercel')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.netlify')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.render')));
  assert(findings.some((finding) => finding.message.includes('~/.config/fly')));
  assert(findings.some((finding) => finding.message.includes('/root/.railway')));
});

test('host observability tool credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  datadog:
    image: datadog/agent:7.66.1
    volumes:
      - \${HOME}/.datadog:/run/datadog-creds:ro
      - /tmp/cache:/cache
  sentry:
    image: getsentry/sentry-cli:2.44.0
    volumes:
      - /home/alice/.sentryclirc:/root/.sentryclirc:ro
  newrelic:
    image: newrelic:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.newrelic
        target: /root/.newrelic
  honeycomb:
    image: honeycombio/buildevents:0.11.3
    volumes:
      - ~/.config/honeycomb:/root/.config/honeycomb:ro
  grafana:
    image: grafana:1.0.0
    volumes:
      - /root/.config/grafana:/root/.config/grafana:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG051', 'CRG051', 'CRG051', 'CRG051', 'CRG051']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.datadog')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.sentryclirc')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.newrelic')));
  assert(findings.some((finding) => finding.message.includes('~/.config/honeycomb')));
  assert(findings.some((finding) => finding.message.includes('/root/.config/grafana')));
});

test('host payment processor credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  stripe:
    image: stripe/stripe-cli:v1.27.0
    volumes:
      - \${HOME}/.config/stripe:/root/.config/stripe:ro
      - /tmp/cache:/cache
  stripe-legacy:
    image: stripe/stripe-cli:v1.27.0
    volumes:
      - /home/alice/.stripe:/root/.stripe:ro
  razorpay:
    image: razorpay:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.config/razorpay
        target: /root/.config/razorpay
  paddle:
    image: paddle:1.0.0
    volumes:
      - ~/.config/paddle:/root/.config/paddle:ro
  square:
    image: square:1.0.0
    volumes:
      - /root/.config/square:/root/.config/square:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG052', 'CRG052', 'CRG052', 'CRG052', 'CRG052']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/stripe')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.stripe')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/razorpay')));
  assert(findings.some((finding) => finding.message.includes('~/.config/paddle')));
  assert(findings.some((finding) => finding.message.includes('/root/.config/square')));
});

test('host collaboration app credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  slack:
    image: node:20
    volumes:
      - \${HOME}/.config/slack:/root/.config/slack:ro
      - /tmp/cache:/cache
  discord:
    image: node:20
    volumes:
      - /home/alice/.config/discord:/root/.config/discord:ro
  teams:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/Microsoft/Teams
        target: /root/.config/teams
  mattermost:
    image: node:20
    volumes:
      - ~/.mattermost:/root/.mattermost:ro
  zoom:
    image: node:20
    volumes:
      - /root/.config/zoom:/root/.config/zoom:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG053', 'CRG053', 'CRG053', 'CRG053', 'CRG053']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/slack')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/discord')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/Microsoft/Teams')));
  assert(findings.some((finding) => finding.message.includes('~/.mattermost')));
  assert(findings.some((finding) => finding.message.includes('/root/.config/zoom')));
});

test('host email client credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  thunderbird:
    image: node:20
    volumes:
      - \${HOME}/.thunderbird:/profiles/thunderbird:ro
      - /tmp/cache:/cache
  aerc:
    image: node:20
    volumes:
      - /home/alice/.config/aerc:/root/.config/aerc:ro
  apple-mail:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/Library/Mail
        target: /host-mail
  mutt:
    image: node:20
    volumes:
      - ~/.mutt:/root/.mutt:ro
  msmtp:
    image: node:20
    volumes:
      - /root/.msmtprc:/root/.msmtprc:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG054', 'CRG054', 'CRG054', 'CRG054', 'CRG054']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.thunderbird')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/aerc')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Mail')));
  assert(findings.some((finding) => finding.message.includes('~/.mutt')));
  assert(findings.some((finding) => finding.message.includes('/root/.msmtprc')));
});

test('host password manager credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  bitwarden:
    image: node:20
    volumes:
      - \${HOME}/.config/Bitwarden:/root/.config/Bitwarden:ro
      - /tmp/cache:/cache
  bitwarden-cli:
    image: node:20
    volumes:
      - /home/alice/.config/Bitwarden CLI:/root/.config/Bitwarden CLI:ro
  keepassxc:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/KeePassXC
        target: /host/keepassxc
  keepass-data:
    image: node:20
    volumes:
      - ~/.local/share/keepassxc:/root/.local/share/keepassxc:ro
  vault-file:
    image: node:20
    volumes:
      - /vaults/prod.kdbx:/run/prod.kdbx:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG055', 'CRG055', 'CRG055', 'CRG055', 'CRG055']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/Bitwarden')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/Bitwarden CLI')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/KeePassXC')));
  assert(findings.some((finding) => finding.message.includes('~/.local/share/keepassxc')));
  assert(findings.some((finding) => finding.message.includes('/vaults/prod.kdbx')));
});

test('host local LLM runtime data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  ollama:
    image: node:20
    volumes:
      - \${HOME}/.ollama:/root/.ollama:ro
      - /tmp/cache:/cache
  lmstudio:
    image: node:20
    volumes:
      - /home/alice/.lmstudio:/root/.lmstudio:ro
  huggingface:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/.cache/huggingface/hub
        target: /models/hf
  jan:
    image: node:20
    volumes:
      - ~/Library/Application Support/Jan:/host/jan:ro
  llamacpp:
    image: node:20
    volumes:
      - /root/.cache/llama.cpp:/models/llama.cpp:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG056', 'CRG056', 'CRG056', 'CRG056', 'CRG056']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.ollama')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.lmstudio')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.cache/huggingface/hub')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Application Support/Jan')));
  assert(findings.some((finding) => finding.message.includes('/root/.cache/llama.cpp')));
});

test('host API client credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  httpie:
    image: node:20
    volumes:
      - \${HOME}/.config/httpie:/root/.config/httpie:ro
      - /tmp/cache:/cache
  postman:
    image: node:20
    volumes:
      - /home/alice/.config/postman:/root/.config/postman:ro
  insomnia:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/.config/Insomnia
        target: /root/.config/Insomnia
  bruno:
    image: node:20
    volumes:
      - ~/.bruno:/root/.bruno:ro
  curl:
    image: curlimages/curl:8.14.1
    volumes:
      - /root/.curlrc:/root/.curlrc:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG057', 'CRG057', 'CRG057', 'CRG057', 'CRG057']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/httpie')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/postman')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/Insomnia')));
  assert(findings.some((finding) => finding.message.includes('~/.bruno')));
  assert(findings.some((finding) => finding.message.includes('/root/.curlrc')));
});

test('host CI/CD service credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  circleci:
    image: node:20
    volumes:
      - \${HOME}/.circleci:/root/.circleci:ro
      - /tmp/cache:/cache
  buildkite:
    image: node:20
    volumes:
      - /home/alice/.buildkite:/root/.buildkite:ro
  gitlab:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/.config/glab-cli
        target: /root/.config/glab-cli
  drone:
    image: node:20
    volumes:
      - ~/.config/drone:/root/.config/drone:ro
  jenkins:
    image: jenkins/jenkins:2.516.1
    volumes:
      - /root/.jenkins:/host-jenkins:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG058', 'CRG058', 'CRG058', 'CRG058', 'CRG058']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.circleci')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.buildkite')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/glab-cli')));
  assert(findings.some((finding) => finding.message.includes('~/.config/drone')));
  assert(findings.some((finding) => finding.message.includes('/root/.jenkins')));
});

test('host certificate authority and TLS private key bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  step:
    image: smallstep/step-cli:0.28.4
    volumes:
      - \${HOME}/.step:/root/.step:ro
      - /tmp/cache:/cache
  mkcert:
    image: node:20
    volumes:
      - /home/alice/.local/share/mkcert:/root/.local/share/mkcert:ro
  cfssl:
    image: cfssl/cfssl:1.6.5
    volumes:
      - type: bind
        source: /Users/alice/.cfssl
        target: /root/.cfssl
  system:
    image: alpine:3.22
    volumes:
      - /etc/ssl/private:/host-ssl-private:ro
  keyfile:
    image: alpine:3.22
    volumes:
      - ./root_ca_key.pem:/run/root_ca_key.pem:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG059', 'CRG059', 'CRG059', 'CRG059', 'CRG059']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.step')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.local/share/mkcert')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.cfssl')));
  assert(findings.some((finding) => finding.message.includes('/etc/ssl/private')));
  assert(findings.some((finding) => finding.message.includes('./root_ca_key.pem')));
});

test('host secret manager credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  vault:
    image: hashicorp/vault:1.19
    volumes:
      - \${HOME}/.vault-token:/root/.vault-token:ro
      - /tmp/cache:/cache
  onepassword:
    image: 1password/op:2
    volumes:
      - type: bind
        source: /Users/alice/.config/op
        target: /root/.config/op
  doppler:
    image: dopplerhq/cli:3
    volumes:
      - ~/.config/doppler:/root/.config/doppler:ro
  infisical:
    image: infisical/cli:0.42.1
    volumes:
      - /home/alice/.config/infisical:/root/.config/infisical:ro
  akeyless:
    image: akeyless/base:1.0.0
    volumes:
      - /root/.akeyless:/host-akeyless:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG060', 'CRG060', 'CRG060', 'CRG060', 'CRG060']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.vault-token')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/op')));
  assert(findings.some((finding) => finding.message.includes('~/.config/doppler')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/infisical')));
  assert(findings.some((finding) => finding.message.includes('/root/.akeyless')));
});

test('host shell startup file bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  bash:
    image: bash:5.2
    volumes:
      - \${HOME}/.bashrc:/root/.bashrc:ro
      - /tmp/cache:/cache
  zsh:
    image: zsh:5.9
    volumes:
      - /home/alice/.zprofile:/root/.zprofile:ro
  fish:
    image: fish:4.0
    volumes:
      - type: bind
        source: /Users/alice/.config/fish/config.fish
        target: /root/.config/fish/config.fish
  profile:
    image: alpine:3.22
    volumes:
      - ~/.profile:/root/.profile:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG061', 'CRG061', 'CRG061', 'CRG061']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.bashrc')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.zprofile')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/fish/config.fish')));
  assert(findings.some((finding) => finding.message.includes('~/.profile')));
});

test('host editor and IDE state bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  vscode:
    image: node:20
    volumes:
      - \${HOME}/.vscode:/root/.vscode:ro
      - /tmp/cache:/cache
  code:
    image: node:20
    volumes:
      - /home/alice/.config/Code/User/globalStorage:/tmp/code-state:ro
  jetbrains:
    image: idea:2025.1
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/JetBrains
        target: /root/.config/JetBrains
  zed:
    image: zed:1.0.0
    volumes:
      - ~/.config/zed:/root/.config/zed:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG062', 'CRG062', 'CRG062', 'CRG062']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.vscode')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/Code')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/JetBrains')));
  assert(findings.some((finding) => finding.message.includes('~/.config/zed')));
});

test('host terminal emulator state bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  kitty:
    image: node:20
    volumes:
      - \${HOME}/.config/kitty:/root/.config/kitty:ro
      - /tmp/cache:/cache
  wezterm:
    image: node:20
    volumes:
      - /home/alice/.config/wezterm:/root/.config/wezterm:ro
  iterm:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/iTerm2
        target: /host-iterm
  ghostty:
    image: node:20
    volumes:
      - ~/.config/ghostty:/root/.config/ghostty:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG063', 'CRG063', 'CRG063', 'CRG063']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/kitty')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/wezterm')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/iTerm2')));
  assert(findings.some((finding) => finding.message.includes('~/.config/ghostty')));
});

test('host notes and knowledge-base data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  obsidian:
    image: node:20
    volumes:
      - \${HOME}/Documents/Vault/.obsidian:/vault/.obsidian:ro
      - /tmp/cache:/cache
  logseq:
    image: node:20
    volumes:
      - /home/alice/.config/logseq:/root/.config/logseq:ro
  notion:
    image: node:20
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/Notion
        target: /host-notion
  notes:
    image: node:20
    volumes:
      - ~/Library/Group Containers/group.com.apple.notes:/host-notes:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG064', 'CRG064', 'CRG064', 'CRG064']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/Documents/Vault/.obsidian')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/logseq')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/Notion')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Group Containers/group.com.apple.notes')));
});

test('host OS keychain and keyring bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  gnome:
    image: node:20
    volumes:
      - \${HOME}/.local/share/keyrings:/host-keyrings:ro
      - /tmp/cache:/cache
  legacy:
    image: node:20
    volumes:
      - /home/alice/.gnome2/keyrings:/host-gnome-keyrings:ro
  kwallet:
    image: node:20
    volumes:
      - type: bind
        source: /root/.config/kwalletd
        target: /host-kwallet
  macos:
    image: node:20
    volumes:
      - ~/Library/Keychains/login.keychain-db:/host-login.keychain-db:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG065', 'CRG065', 'CRG065', 'CRG065']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.local/share/keyrings')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.gnome2/keyrings')));
  assert(findings.some((finding) => finding.message.includes('/root/.config/kwalletd')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Keychains/login.keychain-db')));
});

test('host hardware authenticator and passkey state bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  yubikey:
    image: node:20
    volumes:
      - \${HOME}/.config/Yubico:/host-yubico:ro
      - /tmp/cache:/cache
  fido:
    image: node:20
    volumes:
      - /home/alice/.config/libfido2:/host-fido:ro
  webauthn:
    image: node:20
    volumes:
      - type: bind
        source: /root/.local/share/webauthn
        target: /host-webauthn
  macos:
    image: node:20
    volumes:
      - ~/Library/Application Support/Yubico:/host-macos-yubico:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG066', 'CRG066', 'CRG066', 'CRG066']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/Yubico')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/libfido2')));
  assert(findings.some((finding) => finding.message.includes('/root/.local/share/webauthn')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Application Support/Yubico')));
});

test('host browser automation session state bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  playwright:
    image: mcr.microsoft.com/playwright:v1.52.0
    volumes:
      - \${HOME}/.cache/ms-playwright:/root/.cache/ms-playwright:ro
      - /tmp/cache:/cache
  puppeteer:
    image: node:20
    volumes:
      - /home/alice/.cache/puppeteer:/root/.cache/puppeteer:ro
  cypress:
    image: cypress/included:14.4.0
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/Cypress
        target: /host-cypress
  selenium:
    image: selenium/standalone-chrome:4.33.0
    volumes:
      - ~/.config/selenium:/root/.config/selenium:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG067', 'CRG067', 'CRG067', 'CRG067']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.cache/ms-playwright')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.cache/puppeteer')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/Cypress')));
  assert(findings.some((finding) => finding.message.includes('~/.config/selenium')));
});

test('host private sync identity bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  syncthing:
    image: syncthing/syncthing:1.29
    volumes:
      - \${HOME}/.config/syncthing:/host-syncthing:ro
      - /tmp/cache:/cache
  linux-state:
    image: alpine:3.22
    volumes:
      - /home/alice/.local/state/syncthing:/host-state:ro
  resilio:
    image: resilio/sync:3.1
    volumes:
      - type: bind
        source: /var/lib/resilio-sync
        target: /host-resilio
  macos:
    image: alpine:3.22
    volumes:
      - ~/Library/Application Support/Resilio Sync:/host-macos-resilio:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG068', 'CRG068', 'CRG068', 'CRG068']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/syncthing')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.local/state/syncthing')));
  assert(findings.some((finding) => finding.message.includes('/var/lib/resilio-sync')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Application Support/Resilio Sync')));
});

test('host remote access credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  anydesk:
    image: node:20
    volumes:
      - \${HOME}/.anydesk:/host-anydesk:ro
      - /tmp/cache:/cache
  teamviewer:
    image: node:20
    volumes:
      - /home/alice/.config/teamviewer:/host-teamviewer:ro
  system:
    image: node:20
    volumes:
      - type: bind
        source: /var/lib/anydesk
        target: /host-anydesk-system
  rustdesk:
    image: node:20
    volumes:
      - ~/Library/Application Support/RustDesk:/host-rustdesk:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG069', 'CRG069', 'CRG069', 'CRG069']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.anydesk')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.config/teamviewer')));
  assert(findings.some((finding) => finding.message.includes('/var/lib/anydesk')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Application Support/RustDesk')));
});

test('host language runtime package cache bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  npm:
    image: node:20
    volumes:
      - \${HOME}/.npm:/root/.npm:ro
      - /tmp/cache:/cache
  pip:
    image: python:3.12
    volumes:
      - /home/alice/.cache/pip:/root/.cache/pip:ro
  cargo:
    image: rust:1.85
    volumes:
      - type: bind
        source: /Users/alice/.cargo/registry
        target: /usr/local/cargo/registry
  yarn:
    image: node:20
    volumes:
      - ~/Library/Caches/Yarn:/host-yarn-cache:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG070', 'CRG070', 'CRG070', 'CRG070']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.npm')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.cache/pip')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.cargo/registry')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Caches/Yarn')));
});

test('host mobile app signing credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  android:
    image: gradle:8.14
    volumes:
      - \${HOME}/.android/debug.keystore:/root/.android/debug.keystore:ro
      - /tmp/cache:/cache
  release:
    image: gradle:8.14
    volumes:
      - /home/alice/releases/upload-key.jks:/run/signing/upload-key.jks:ro
  xcode:
    image: xcode-builder:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/Library/MobileDevice/Provisioning Profiles
        target: /profiles
  appstore:
    image: fastlane:2.227
    volumes:
      - ~/.appstoreconnect/private_keys/AuthKey_ABC123.p8:/keys/AuthKey_ABC123.p8:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG071', 'CRG071', 'CRG071', 'CRG071']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.android/debug.keystore')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/releases/upload-key.jks')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/MobileDevice/Provisioning Profiles')));
  assert(findings.some((finding) => finding.message.includes('~/.appstoreconnect/private_keys/AuthKey_ABC123.p8')));
});

test('host VPN client profile bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  wireguard:
    image: linuxserver/wireguard:1.0.20250521
    volumes:
      - \${HOME}/.config/wireguard/wg0.conf:/config/wg0.conf:ro
      - /tmp/cache:/cache
  openvpn:
    image: openvpn:2.6
    volumes:
      - /home/alice/.openvpn/client.ovpn:/etc/openvpn/client.ovpn:ro
  mac:
    image: vpn-helper:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/Tunnelblick
        target: /tunnelblick
  system:
    image: alpine:3.22
    volumes:
      - /etc/wireguard:/host-wireguard:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG072', 'CRG072', 'CRG072', 'CRG072']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/wireguard/wg0.conf')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.openvpn/client.ovpn')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/Tunnelblick')));
  assert(findings.some((finding) => finding.message.includes('/etc/wireguard')));
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

test('host artifact signing credential bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  cosign:
    image: cgr.dev/chainguard/cosign:2.2.4
    volumes:
      - \${HOME}/.sigstore:/root/.sigstore:ro
      - /tmp/cache:/cache
  notation:
    image: notation:1.0.0
    volumes:
      - type: bind
        source: /Users/alice/.config/notation
        target: /root/.config/notation
  minisign:
    image: alpine:3.22
    volumes:
      - /home/alice/minisign.key:/run/minisign.key:ro
  notary:
    image: notary:1.0.0
    volumes:
      - ~/.notary:/root/.notary:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG073', 'CRG073', 'CRG073', 'CRG073']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.sigstore')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/.config/notation')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/minisign.key')));
  assert(findings.some((finding) => finding.message.includes('~/.notary')));
});

test('host calendar and contact data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  khal:
    image: python:3.12
    volumes:
      - \${HOME}/.config/khal:/root/.config/khal:ro
      - /tmp/cache:/cache
  evolution:
    image: alpine:3.22
    volumes:
      - /home/alice/.local/share/evolution:/root/evolution:ro
  contacts:
    image: alpine:3.22
    volumes:
      - type: bind
        source: /Users/alice/Library/Application Support/AddressBook
        target: /contacts
  calendars:
    image: alpine:3.22
    volumes:
      - ~/Library/Calendars:/calendars:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG074', 'CRG074', 'CRG074', 'CRG074']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/khal')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.local/share/evolution')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/AddressBook')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Calendars')));
});

test('host messaging app data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  signal:
    image: alpine:3.22
    volumes:
      - \${HOME}/.config/Signal:/root/.config/Signal:ro
      - /tmp/cache:/cache
  telegram:
    image: alpine:3.22
    volumes:
      - /home/alice/.local/share/TelegramDesktop/tdata:/telegram/tdata:ro
  imessage:
    image: alpine:3.22
    volumes:
      - type: bind
        source: /Users/alice/Library/Messages
        target: /messages
  macsignal:
    image: alpine:3.22
    volumes:
      - ~/Library/Application Support/Signal:/signal:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG075', 'CRG075', 'CRG075', 'CRG075']
  );
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/Signal')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.local/share/TelegramDesktop/tdata')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Messages')));
  assert(findings.some((finding) => finding.message.includes('~/Library/Application Support/Signal')));
});

test('host tax or accounting app data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  linux:
    image: alpine:3.22
    volumes:
      - ~/.config/gnucash:/host-gnucash:ro
      - /home/alice/Documents/TurboTax/2025.tax2025:/tax:ro
  mac:
    image: alpine:3.22
    volumes:
      - /Users/alice/Library/Application Support/QuickBooks:/quickbooks:ro
      - ~/Documents/H&R Block/return.tax24:/return:ro
  named:
    image: alpine:3.22
    volumes:
      - business_data:/data
volumes:
  business_data:
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG077', 'CRG077', 'CRG077', 'CRG077']
  );
  assert(findings.some((finding) => finding.message.includes('~/.config/gnucash')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/Documents/TurboTax/2025.tax2025')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Library/Application Support/QuickBooks')));
  assert(findings.some((finding) => finding.message.includes('~/Documents/H&R Block/return.tax24')));
});

test('host photo library data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  photos:
    image: alpine:3.22
    volumes:
      - ~/Pictures/Photos Library.photoslibrary:/photos:ro
      - /tmp/cache:/cache
  lightroom:
    image: alpine:3.22
    volumes:
      - /Users/alice/Pictures/Lightroom/Catalog.lrcat:/catalog:ro
  digikam:
    image: alpine:3.22
    volumes:
      - type: bind
        source: /home/alice/.local/share/digikam
        target: /digikam
  linuxconfig:
    image: alpine:3.22
    volumes:
      - \${HOME}/.config/digikamrc:/digikamrc:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG078', 'CRG078', 'CRG078', 'CRG078']
  );
  assert(findings.some((finding) => finding.message.includes('~/Pictures/Photos Library.photoslibrary')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Pictures/Lightroom/Catalog.lrcat')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.local/share/digikam')));
  assert(findings.some((finding) => finding.message.includes('${HOME}/.config/digikamrc')));
});

test('host music or media library data bind mounts are reported', () => {
  const dir = fixture({
    'compose.yml': `
services:
  apple:
    image: alpine:3.22
    volumes:
      - ~/Music/Music Library.musiclibrary:/music:ro
      - /tmp/cache:/cache
  itunes:
    image: alpine:3.22
    volumes:
      - /Users/alice/Music/iTunes/iTunes Library.itl:/itunes.itl:ro
  rhythmbox:
    image: alpine:3.22
    volumes:
      - type: bind
        source: /home/alice/.local/share/rhythmbox
        target: /rhythmbox
  plexamp:
    image: alpine:3.22
    volumes:
      - \${HOME}/Library/Application Support/Plexamp:/plexamp:ro
`
  });

  const findings = scanProject(dir);
  assert.equal(findings.length, 4);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG079', 'CRG079', 'CRG079', 'CRG079']
  );
  assert(findings.some((finding) => finding.message.includes('~/Music/Music Library.musiclibrary')));
  assert(findings.some((finding) => finding.message.includes('/Users/alice/Music/iTunes/iTunes Library.itl')));
  assert(findings.some((finding) => finding.message.includes('/home/alice/.local/share/rhythmbox')));
  assert(findings.some((finding) => finding.message.includes('${HOME}/Library/Application Support/Plexamp')));
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
