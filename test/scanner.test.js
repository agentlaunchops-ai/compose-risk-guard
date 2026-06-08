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
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['CRG009', 'CRG009']
  );
  assert(findings.some((finding) => finding.message.includes('SYS_PTRACE')));
  assert(findings.some((finding) => finding.message.includes('NET_ADMIN')));
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
