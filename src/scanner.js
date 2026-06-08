import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

export const rules = {
  CRG001: 'Secret-like environment variable has a literal value',
  CRG002: 'Referenced env file contains a secret-like literal',
  CRG003: 'Service runs with privileged: true',
  CRG004: 'Service bind-mounts the Docker socket',
  CRG005: 'Service shares a host namespace',
  CRG006: 'Service bind-mounts a sensitive host path',
  CRG007: 'Service image uses latest or has no explicit tag/digest',
  CRG008: 'Secret-like build argument has a literal value',
  CRG009: 'Service adds a high-risk Linux capability',
  CRG010: 'Service disables a container security profile',
  CRG011: 'Service publishes a sensitive port on all interfaces',
  CRG012: 'Service explicitly runs as root',
  CRG013: 'Service shares an additional host namespace'
};

const composeNames = new Set([
  'compose.yml',
  'compose.yaml',
  'docker-compose.yml',
  'docker-compose.yaml'
]);

const secretKeyPattern = /(^|_)(password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|auth|credential)s?($|_)/i;
const substitutionPattern = /^\$\{[^}]+}$/;
const sensitiveHostPaths = [
  '/etc',
  '/root',
  '/home',
  '/var/lib/docker',
  '/var/run',
  '/usr/lib',
  '/boot'
];
const riskyCapabilities = new Set([
  'SYS_ADMIN',
  'SYS_MODULE',
  'SYS_PTRACE',
  'NET_ADMIN',
  'DAC_READ_SEARCH',
  'DAC_OVERRIDE'
]);
const sensitivePorts = new Set([
  11211, // Memcached
  2181, // ZooKeeper
  2375, // Docker API
  3306, // MySQL
  5432, // PostgreSQL
  5601, // Kibana
  5672, // RabbitMQ
  5984, // CouchDB
  6379, // Redis
  8086, // InfluxDB
  9092, // Kafka
  9200, // Elasticsearch
  9300, // Elasticsearch transport
  15672, // RabbitMQ management
  27017 // MongoDB
]);

export function discoverComposeFiles(rootDir) {
  const found = [];
  walk(rootDir, found);
  return found.sort();
}

function walk(dir, found) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath, found);
    } else if (entry.isFile() && isComposeName(entry.name)) {
      found.push(fullPath);
    }
  }
}

function isComposeName(name) {
  return composeNames.has(name) || /^docker-compose\.[\w.-]+\.(ya?ml)$/i.test(name);
}

export function scanProject(rootDir) {
  return discoverComposeFiles(rootDir).flatMap((filePath) => scanComposeFile(filePath, rootDir));
}

export function scanComposeFile(filePath, rootDir = path.dirname(filePath)) {
  const text = fs.readFileSync(filePath, 'utf8');
  let doc;
  try {
    doc = yaml.load(text, { filename: filePath }) || {};
  } catch (error) {
    return [finding('CRG000', `Compose YAML could not be parsed: ${error.reason || error.message}`, filePath, 1)];
  }

  const services = doc.services && typeof doc.services === 'object' ? doc.services : {};
  const findings = [];
  for (const [serviceName, service] of Object.entries(services)) {
    if (!service || typeof service !== 'object') continue;
    findings.push(...scanEnvironment(service, serviceName, filePath, text));
    findings.push(...scanEnvFiles(service, serviceName, filePath, rootDir));
    findings.push(...scanHostAccess(service, serviceName, filePath, text));
    findings.push(...scanImage(service, serviceName, filePath, text));
    findings.push(...scanBuildArgs(service, serviceName, filePath, text));
    findings.push(...scanSecurityOptions(service, serviceName, filePath, text));
    findings.push(...scanPublishedPorts(service, serviceName, filePath, text));
    findings.push(...scanUser(service, serviceName, filePath, text));
  }
  return findings;
}

function scanEnvironment(service, serviceName, filePath, text) {
  const env = service.environment;
  if (!env) return [];
  const entries = Array.isArray(env)
    ? env.map((item) => {
        const [key, ...rest] = String(item).split('=');
        return [key, rest.join('=')];
      })
    : Object.entries(env);

  return entries.flatMap(([key, value]) => {
    if (!isSecretLiteral(key, value)) return [];
    return [
      finding(
        'CRG001',
        `${serviceName} sets secret-like environment variable ${key} with a literal value`,
        filePath,
        lineFor(text, key)
      )
    ];
  });
}

function scanEnvFiles(service, serviceName, composePath, rootDir) {
  const refs = normalizeEnvFiles(service.env_file);
  const findings = [];
  for (const ref of refs) {
    const envPath = path.resolve(path.dirname(composePath), ref);
    if (!isSubpath(rootDir, envPath) || !fs.existsSync(envPath)) continue;
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    lines.forEach((line, index) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) return;
      const [key, ...rest] = trimmed.split('=');
      const value = rest.join('=');
      if (!isSecretLiteral(key, value)) return;
      findings.push(
        finding(
          'CRG002',
          `${serviceName} env_file ${ref} contains secret-like literal ${key}`,
          envPath,
          index + 1
        )
      );
    });
  }
  return findings;
}

function normalizeEnvFiles(value) {
  if (!value) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) {
    return value.flatMap((item) => {
      if (typeof item === 'string') return [item];
      if (item && typeof item === 'object' && typeof item.path === 'string') return [item.path];
      return [];
    });
  }
  return [];
}

function scanHostAccess(service, serviceName, filePath, text) {
  const findings = [];
  if (service.privileged === true) {
    findings.push(finding('CRG003', `${serviceName} runs with privileged: true`, filePath, lineFor(text, 'privileged')));
  }

  for (const mount of normalizeVolumes(service.volumes)) {
    if (mount.source === '/var/run/docker.sock') {
      findings.push(
        finding('CRG004', `${serviceName} bind-mounts /var/run/docker.sock`, filePath, lineFor(text, 'docker.sock'))
      );
      continue;
    }
    if (mount.type === 'bind' && isSensitiveHostPath(mount.source)) {
      findings.push(
        finding('CRG006', `${serviceName} bind-mounts sensitive host path ${mount.source}`, filePath, lineFor(text, mount.source))
      );
    }
  }

  for (const key of ['network_mode', 'pid', 'ipc']) {
    if (service[key] === 'host') {
      findings.push(finding('CRG005', `${serviceName} uses ${key}: host`, filePath, lineFor(text, key)));
    }
  }

  for (const key of ['cgroup', 'uts', 'userns_mode']) {
    if (service[key] === 'host') {
      findings.push(finding('CRG013', `${serviceName} uses ${key}: host`, filePath, lineFor(text, key)));
    }
  }

  for (const capability of normalizeCapabilities(service.cap_add)) {
    if (!riskyCapabilities.has(capability)) continue;
    findings.push(
      finding(
        'CRG009',
        `${serviceName} adds high-risk Linux capability ${capability}`,
        filePath,
        lineFor(text, capability)
      )
    );
  }
  return findings;
}

function normalizeCapabilities(value) {
  const entries = Array.isArray(value) ? value : [value];
  return entries
    .filter((item) => typeof item === 'string')
    .map((item) => item.trim().toUpperCase().replace(/^CAP_/, ''))
    .filter(Boolean);
}

function normalizeVolumes(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === 'string') {
      const [source, target, mode = ''] = item.split(':');
      if (!target || !source.startsWith('/')) return [];
      return [{ type: 'bind', source, target, mode }];
    }
    if (item && typeof item === 'object') {
      const type = item.type || (String(item.source || '').startsWith('/') ? 'bind' : 'volume');
      return [{ type, source: item.source || item.src || '', target: item.target || item.dst || item.destination || '' }];
    }
    return [];
  });
}

function scanImage(service, serviceName, filePath, text) {
  if (typeof service.image !== 'string') return [];
  const image = service.image;
  if (image.includes('@sha256:')) return [];
  const namePart = image.split('/').pop() || image;
  const tag = namePart.includes(':') ? namePart.split(':').pop() : '';
  if (tag && tag !== 'latest') return [];
  return [
    finding(
      'CRG007',
      `${serviceName} image ${image} is not pinned to a non-latest tag or digest`,
      filePath,
      lineFor(text, `image: ${image}`)
    )
  ];
}

function scanBuildArgs(service, serviceName, filePath, text) {
  const args = service.build && typeof service.build === 'object' ? service.build.args : null;
  if (!args) return [];
  const entries = Array.isArray(args)
    ? args.map((item) => {
        const [key, ...rest] = String(item).split('=');
        return [key, rest.join('=')];
      })
    : Object.entries(args);

  return entries.flatMap(([key, value]) => {
    if (!isSecretLiteral(key, value)) return [];
    return [
      finding(
        'CRG008',
        `${serviceName} sets secret-like build argument ${key} with a literal value`,
        filePath,
        lineFor(text, key)
      )
    ];
  });
}

function scanSecurityOptions(service, serviceName, filePath, text) {
  const disabledOptions = normalizeSecurityOptions(service.security_opt).filter(isDisabledSecurityOption);
  return disabledOptions.map((option) =>
    finding(
      'CRG010',
      `${serviceName} disables a container security profile with security_opt: ${option}`,
      filePath,
      lineFor(text, option)
    )
  );
}

function scanPublishedPorts(service, serviceName, filePath, text) {
  return normalizePorts(service.ports)
    .filter((port) => sensitivePorts.has(port.target) && isPublicHostIp(port.hostIp))
    .map((port) =>
      finding(
        'CRG011',
        `${serviceName} publishes sensitive port ${port.target} on all interfaces`,
        filePath,
        lineFor(text, port.raw)
      )
    );
}

function scanUser(service, serviceName, filePath, text) {
  if (!runsAsRoot(service.user)) return [];
  return [
    finding(
      'CRG012',
      `${serviceName} explicitly runs as root with user: ${service.user}`,
      filePath,
      lineFor(text, 'user:')
    )
  ];
}

function normalizePorts(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === 'number') return [{ target: item, hostIp: '', raw: String(item) }];
    if (typeof item === 'string') return parsePortString(item);
    if (!item || typeof item !== 'object') return [];
    const target = Number(item.target);
    if (!Number.isInteger(target)) return [];
    return [
      {
        target,
        hostIp: String(item.host_ip || item.hostIp || ''),
        raw: String(item.target)
      }
    ];
  });
}

function parsePortString(item) {
  const raw = item;
  const value = item.trim().replace(/\/(tcp|udp|sctp)$/i, '');
  if (!value) return [];
  const parts = value.split(':');
  const target = Number(parts.at(-1));
  if (!Number.isInteger(target)) return [];
  const hostIp = parts.length >= 3 ? parts.slice(0, -2).join(':').replace(/^\[|\]$/g, '') : '';
  return [{ target, hostIp, raw }];
}

function normalizeSecurityOptions(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((item) => typeof item === 'string');
  return [];
}

function isDisabledSecurityOption(option) {
  const normalized = option.trim().toLowerCase();
  return (
    normalized === 'no-new-privileges:false' ||
    normalized === 'seccomp:unconfined' ||
    normalized === 'apparmor:unconfined' ||
    normalized === 'label:disable'
  );
}

function isPublicHostIp(hostIp) {
  const normalized = String(hostIp || '').trim().toLowerCase();
  return normalized === '' || normalized === '0.0.0.0' || normalized === '::' || normalized === '[::]';
}

function runsAsRoot(value) {
  if (typeof value === 'number') return value === 0;
  if (typeof value !== 'string') return false;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return false;
  const [user] = normalized.split(':');
  return user === 'root' || user === '0';
}

function isSecretLiteral(key, value) {
  if (!key || !secretKeyPattern.test(String(key))) return false;
  if (String(key).endsWith('_FILE')) return false;
  const normalized = value == null ? '' : String(value).trim();
  if (!normalized || substitutionPattern.test(normalized)) return false;
  if (/^(true|false|null)$/i.test(normalized)) return false;
  return true;
}

function isSensitiveHostPath(source) {
  return sensitiveHostPaths.some((candidate) => source === candidate || source.startsWith(`${candidate}/`));
}

function isSubpath(rootDir, targetPath) {
  const relative = path.relative(path.resolve(rootDir), path.resolve(targetPath));
  return relative && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function lineFor(text, needle) {
  const lines = text.split(/\r?\n/);
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

function finding(ruleId, message, filePath, line) {
  return {
    ruleId,
    message,
    filePath,
    line,
    severity: ruleId === 'CRG007' ? 'warning' : 'error'
  };
}

export function formatText(findings, rootDir = process.cwd()) {
  if (findings.length === 0) return 'compose-risk-guard: no findings';
  return findings
    .map((item) => {
      const rel = path.relative(rootDir, item.filePath) || item.filePath;
      return `${rel}:${item.line} ${item.ruleId} ${item.message}`;
    })
    .join('\n');
}

export function toSarif(findings, rootDir = process.cwd()) {
  const usedRules = new Set(findings.map((item) => item.ruleId));
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'compose-risk-guard',
            informationUri: 'https://github.com/agentlaunchops-ai/compose-risk-guard',
            rules: [...usedRules].map((id) => ({
              id,
              name: id,
              shortDescription: { text: rules[id] || 'Compose parse error' },
              defaultConfiguration: { level: id === 'CRG007' ? 'warning' : 'error' }
            }))
          }
        },
        results: findings.map((item) => ({
          ruleId: item.ruleId,
          level: item.severity,
          message: { text: item.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: path.relative(rootDir, item.filePath) || item.filePath },
                region: { startLine: item.line }
              }
            }
          ]
        }))
      }
    ]
  };
}
