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
  CRG013: 'Service shares an additional host namespace',
  CRG014: 'Service maps a sensitive host device',
  CRG015: 'Service maps a hostname to the Docker host gateway',
  CRG016: 'Service disables TLS certificate verification',
  CRG017: 'Service sets a high-risk kernel sysctl',
  CRG018: 'Service disables its container healthcheck',
  CRG019: 'Service disables container logging',
  CRG020: 'Service bind-mounts a container runtime socket',
  CRG021: 'Service bind-mounts a host SSH agent socket',
  CRG022: 'Service adds capabilities without dropping defaults first',
  CRG023: 'Service joins another service namespace',
  CRG024: 'Service explicitly disables a read-only root filesystem',
  CRG025: 'Service label contains a secret-like literal',
  CRG026: 'Service points Docker clients at an insecure TCP daemon',
  CRG027: 'Service build context escapes the scanned project',
  CRG028: 'Service env_file escapes the scanned project',
  CRG029: 'Compose secret file escapes the scanned project',
  CRG030: 'Service bind-mounts host Docker client credentials',
  CRG031: 'Service bind-mounts host cloud provider credentials',
  CRG032: 'Service bind-mounts host Kubernetes credentials',
  CRG033: 'Service bind-mounts host package manager credentials',
  CRG034: 'Service bind-mounts host Git or SSH credentials',
  CRG035: 'Service joins another container namespace',
  CRG036: 'Compose config file escapes the scanned project',
  CRG037: 'Service bind-mounts host build tool credentials',
  CRG038: 'Service bind-mounts dotenv credential files',
  CRG039: 'Service bind-mounts host shell or REPL history files',
  CRG040: 'Service bind-mounts host password store or PGP secrets',
  CRG041: 'Service bind-mounts Terraform or OpenTofu state or credentials',
  CRG042: 'Service bind-mounts SOPS or age secret-management keys',
  CRG043: 'Service bind-mounts cryptocurrency wallet or chain keys',
  CRG044: 'Service bind-mounts host AI provider credentials',
  CRG045: 'Service bind-mounts host browser profile data',
  CRG046: 'Service bind-mounts host database client credentials',
  CRG047: 'Service bind-mounts host backup or sync credentials',
  CRG048: 'Service bind-mounts host container registry credentials or certificates',
  CRG049: 'Service bind-mounts host tunnel or proxy credentials',
  CRG050: 'Service bind-mounts host deployment platform credentials',
  CRG051: 'Service bind-mounts host observability tool credentials',
  CRG052: 'Service bind-mounts host payment processor credentials',
  CRG053: 'Service bind-mounts host collaboration app credentials',
  CRG054: 'Service bind-mounts host email client credentials',
  CRG055: 'Service bind-mounts host password manager vaults or credentials',
  CRG056: 'Service bind-mounts host local LLM runtime data',
  CRG057: 'Service bind-mounts host API client credentials',
  CRG058: 'Service bind-mounts host CI/CD service credentials',
  CRG059: 'Service bind-mounts host certificate authority or TLS private key material',
  CRG060: 'Service bind-mounts host secret manager credentials',
  CRG061: 'Service bind-mounts host shell startup files',
  CRG062: 'Service bind-mounts host editor or IDE state',
  CRG063: 'Service bind-mounts host terminal emulator state',
  CRG064: 'Service bind-mounts host notes or knowledge-base data',
  CRG065: 'Service bind-mounts host OS keychain or keyring data',
  CRG066: 'Service bind-mounts host hardware authenticator or passkey state',
  CRG067: 'Service bind-mounts host browser automation session state',
  CRG068: 'Service bind-mounts host private sync tool identity data',
  CRG069: 'Service bind-mounts host remote access credentials',
  CRG070: 'Service bind-mounts host language runtime package caches',
  CRG071: 'Service bind-mounts host mobile app signing credentials',
  CRG072: 'Service bind-mounts host VPN client profiles or state',
  CRG073: 'Service bind-mounts host artifact signing credentials',
  CRG074: 'Service bind-mounts host calendar or contact data',
  CRG075: 'Service bind-mounts host messaging app data',
  CRG076: 'Service bind-mounts a host credential agent socket',
  CRG077: 'Service bind-mounts host tax or accounting app data'
};

const composeNames = new Set([
  'compose.yml',
  'compose.yaml',
  'docker-compose.yml',
  'docker-compose.yaml'
]);

const secretKeyPattern = /(^|[_.-])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential)s?($|[_.-])/i;
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
const sensitiveDevices = [
  '/dev/bus/usb',
  '/dev/dri',
  '/dev/fuse',
  '/dev/kvm',
  '/dev/mem',
  '/dev/net/tun'
];
const containerRuntimeSockets = [
  '/run/containerd/containerd.sock',
  '/run/crio/crio.sock',
  '/run/docker.sock',
  '/run/podman/podman.sock',
  '/var/run/podman/podman.sock'
];
const sshAgentSockets = [
  '/run/host-services/ssh-auth.sock',
  '/ssh-agent'
];
const insecureTlsEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: (value) => value === '0',
  PYTHONHTTPSVERIFY: (value) => value === '0',
  GIT_SSL_NO_VERIFY: isTruthyString,
  CURL_SSL_NO_VERIFY: isTruthyString,
  AWS_SSL_VERIFY: isFalseyString
};
const riskySysctls = {
  'net.ipv4.ip_forward': isTruthyString,
  'net.ipv4.conf.all.forwarding': isTruthyString,
  'net.ipv4.conf.default.forwarding': isTruthyString,
  'net.ipv4.conf.all.route_localnet': isTruthyString,
  'net.ipv4.conf.default.route_localnet': isTruthyString,
  'kernel.unprivileged_bpf_disabled': (value) => value === '0',
  'kernel.kptr_restrict': (value) => value === '0',
  'kernel.dmesg_restrict': (value) => value === '0'
};

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
  findings.push(...scanSecretFiles(doc, filePath, rootDir, text));
  findings.push(...scanConfigFiles(doc, filePath, rootDir, text));
  for (const [serviceName, service] of Object.entries(services)) {
    if (!service || typeof service !== 'object') continue;
    findings.push(...scanEnvironment(service, serviceName, filePath, text));
    findings.push(...scanEnvFiles(service, serviceName, filePath, rootDir, text));
    findings.push(...scanHostAccess(service, serviceName, filePath, text));
    findings.push(...scanImage(service, serviceName, filePath, text));
    findings.push(...scanBuildContext(service, serviceName, filePath, rootDir, text));
    findings.push(...scanBuildArgs(service, serviceName, filePath, text));
    findings.push(...scanSecurityOptions(service, serviceName, filePath, text));
    findings.push(...scanPublishedPorts(service, serviceName, filePath, text));
    findings.push(...scanUser(service, serviceName, filePath, text));
    findings.push(...scanDevices(service, serviceName, filePath, text));
    findings.push(...scanExtraHosts(service, serviceName, filePath, text));
    findings.push(...scanSysctls(service, serviceName, filePath, text));
    findings.push(...scanHealthcheck(service, serviceName, filePath, text));
    findings.push(...scanLogging(service, serviceName, filePath, text));
    findings.push(...scanReadOnlyRootFs(service, serviceName, filePath, text));
    findings.push(...scanLabels(service, serviceName, filePath, text));
  }
  return findings;
}

function scanSecretFiles(doc, filePath, rootDir, text) {
  const secrets = doc.secrets && typeof doc.secrets === 'object' ? doc.secrets : {};
  return Object.entries(secrets).flatMap(([secretName, secret]) => {
    if (!secret || typeof secret !== 'object' || typeof secret.file !== 'string') return [];
    const ref = secret.file.trim();
    if (!ref || substitutionPattern.test(ref)) return [];
    const secretPath = path.resolve(path.dirname(filePath), ref);
    if (isSubpath(rootDir, secretPath)) return [];
    return [
      finding(
        'CRG029',
        `secret ${secretName} reads file ${ref} outside the scanned project`,
        filePath,
        lineFor(text, ref)
      )
    ];
  });
}

function scanConfigFiles(doc, filePath, rootDir, text) {
  const configs = doc.configs && typeof doc.configs === 'object' ? doc.configs : {};
  return Object.entries(configs).flatMap(([configName, config]) => {
    if (!config || typeof config !== 'object' || typeof config.file !== 'string') return [];
    const ref = config.file.trim();
    if (!ref || substitutionPattern.test(ref)) return [];
    const configPath = path.resolve(path.dirname(filePath), ref);
    if (isSubpath(rootDir, configPath)) return [];
    return [
      finding(
        'CRG036',
        `config ${configName} reads file ${ref} outside the scanned project`,
        filePath,
        lineFor(text, ref)
      )
    ];
  });
}

function scanEnvironment(service, serviceName, filePath, text) {
  const env = service.environment;
  if (!env) return [];
  const entries = normalizeKeyValueEntries(env);

  return entries.flatMap(([key, value]) => {
    const findings = [];
    if (isSecretLiteral(key, value)) {
      findings.push(
        finding(
          'CRG001',
          `${serviceName} sets secret-like environment variable ${key} with a literal value`,
          filePath,
          lineFor(text, key)
        )
      );
    }
    if (isInsecureTlsEnv(key, value)) {
      findings.push(
        finding(
          'CRG016',
          `${serviceName} disables TLS certificate verification with ${key}=${value}`,
          filePath,
          lineFor(text, key)
        )
      );
    }
    if (isInsecureDockerHostEnv(key, value)) {
      findings.push(
        finding(
          'CRG026',
          `${serviceName} points Docker clients at an insecure TCP daemon with ${key}=${value}`,
          filePath,
          lineFor(text, key)
        )
      );
    }
    return findings;
  });
}

function scanEnvFiles(service, serviceName, composePath, rootDir, text) {
  const refs = normalizeEnvFiles(service.env_file);
  const findings = [];
  for (const ref of refs) {
    if (substitutionPattern.test(ref)) continue;
    const envPath = path.resolve(path.dirname(composePath), ref);
    if (!isSubpath(rootDir, envPath)) {
      findings.push(
        finding(
          'CRG028',
          `${serviceName} references env_file ${ref} outside the scanned project`,
          composePath,
          lineFor(text, ref)
        )
      );
      continue;
    }
    if (!fs.existsSync(envPath)) continue;
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    lines.forEach((line, index) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) return;
      const [key, ...rest] = trimmed.split('=');
      const value = rest.join('=');
      if (isSecretLiteral(key, value)) {
        findings.push(
          finding(
            'CRG002',
            `${serviceName} env_file ${ref} contains secret-like literal ${key}`,
            envPath,
            index + 1
          )
        );
      }
      if (isInsecureTlsEnv(key, value)) {
        findings.push(
          finding(
            'CRG016',
            `${serviceName} env_file ${ref} disables TLS certificate verification with ${key}=${value}`,
            envPath,
            index + 1
          )
        );
      }
    });
  }
  return findings;
}

function normalizeKeyValueEntries(value) {
  if (Array.isArray(value)) {
    return value.map((item) => {
      const [key, ...rest] = String(item).split('=');
      return [key, rest.join('=')];
    });
  }
  return Object.entries(value);
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
    if (isContainerRuntimeSocket(mount.source)) {
      findings.push(
        finding(
          'CRG020',
          `${serviceName} bind-mounts container runtime socket ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isSshAgentSocket(mount.source)) {
      findings.push(
        finding(
          'CRG021',
          `${serviceName} bind-mounts host SSH agent socket ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isDockerClientConfigPath(mount.source)) {
      findings.push(
        finding(
          'CRG030',
          `${serviceName} bind-mounts host Docker client credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCloudCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG031',
          `${serviceName} bind-mounts host cloud provider credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isKubernetesCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG032',
          `${serviceName} bind-mounts host Kubernetes credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isPackageManagerCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG033',
          `${serviceName} bind-mounts host package manager credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isBuildToolCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG037',
          `${serviceName} bind-mounts host build tool credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isDotenvCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG038',
          `${serviceName} bind-mounts dotenv credential file ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isShellHistoryPath(mount.source)) {
      findings.push(
        finding(
          'CRG039',
          `${serviceName} bind-mounts host shell or REPL history file ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isPasswordStorePath(mount.source)) {
      findings.push(
        finding(
          'CRG040',
          `${serviceName} bind-mounts host password store or PGP secrets from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isTerraformStateOrCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG041',
          `${serviceName} bind-mounts Terraform or OpenTofu state or credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isSecretManagementKeyPath(mount.source)) {
      findings.push(
        finding(
          'CRG042',
          `${serviceName} bind-mounts SOPS or age secret-management keys from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCryptoWalletKeyPath(mount.source)) {
      findings.push(
        finding(
          'CRG043',
          `${serviceName} bind-mounts cryptocurrency wallet or chain keys from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isAiProviderCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG044',
          `${serviceName} bind-mounts host AI provider credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isBrowserProfilePath(mount.source)) {
      findings.push(
        finding(
          'CRG045',
          `${serviceName} bind-mounts host browser profile data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isDatabaseClientCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG046',
          `${serviceName} bind-mounts host database client credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isBackupOrSyncCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG047',
          `${serviceName} bind-mounts host backup or sync credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isContainerRegistryCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG048',
          `${serviceName} bind-mounts host container registry credentials or certificates from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isTunnelOrProxyCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG049',
          `${serviceName} bind-mounts host tunnel or proxy credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isDeploymentPlatformCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG050',
          `${serviceName} bind-mounts host deployment platform credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isObservabilityCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG051',
          `${serviceName} bind-mounts host observability tool credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isPaymentProcessorCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG052',
          `${serviceName} bind-mounts host payment processor credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCollaborationAppCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG053',
          `${serviceName} bind-mounts host collaboration app credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isEmailClientCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG054',
          `${serviceName} bind-mounts host email client credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isPasswordManagerCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG055',
          `${serviceName} bind-mounts host password manager vaults or credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isLocalLlmRuntimePath(mount.source)) {
      findings.push(
        finding(
          'CRG056',
          `${serviceName} bind-mounts host local LLM runtime data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isApiClientCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG057',
          `${serviceName} bind-mounts host API client credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCiCdCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG058',
          `${serviceName} bind-mounts host CI/CD service credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCertificateAuthorityKeyPath(mount.source)) {
      findings.push(
        finding(
          'CRG059',
          `${serviceName} bind-mounts host certificate authority or TLS private key material from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isSecretManagerCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG060',
          `${serviceName} bind-mounts host secret manager credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isShellStartupPath(mount.source)) {
      findings.push(
        finding(
          'CRG061',
          `${serviceName} bind-mounts host shell startup file ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isEditorOrIdeStatePath(mount.source)) {
      findings.push(
        finding(
          'CRG062',
          `${serviceName} bind-mounts host editor or IDE state from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isTerminalEmulatorStatePath(mount.source)) {
      findings.push(
        finding(
          'CRG063',
          `${serviceName} bind-mounts host terminal emulator state from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isNotesOrKnowledgeBasePath(mount.source)) {
      findings.push(
        finding(
          'CRG064',
          `${serviceName} bind-mounts host notes or knowledge-base data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isOsKeychainPath(mount.source)) {
      findings.push(
        finding(
          'CRG065',
          `${serviceName} bind-mounts host OS keychain or keyring data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isHardwareAuthenticatorOrPasskeyPath(mount.source)) {
      findings.push(
        finding(
          'CRG066',
          `${serviceName} bind-mounts host hardware authenticator or passkey state from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isBrowserAutomationStatePath(mount.source)) {
      findings.push(
        finding(
          'CRG067',
          `${serviceName} bind-mounts host browser automation session state from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isPrivateSyncIdentityPath(mount.source)) {
      findings.push(
        finding(
          'CRG068',
          `${serviceName} bind-mounts host private sync tool identity data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isRemoteAccessCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG069',
          `${serviceName} bind-mounts host remote access credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isLanguageRuntimePackageCachePath(mount.source)) {
      findings.push(
        finding(
          'CRG070',
          `${serviceName} bind-mounts host language runtime package caches from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isMobileSigningCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG071',
          `${serviceName} bind-mounts host mobile app signing credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isVpnClientProfilePath(mount.source)) {
      findings.push(
        finding(
          'CRG072',
          `${serviceName} bind-mounts host VPN client profiles or state from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isArtifactSigningCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG073',
          `${serviceName} bind-mounts host artifact signing credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCalendarOrContactDataPath(mount.source)) {
      findings.push(
        finding(
          'CRG074',
          `${serviceName} bind-mounts host calendar or contact data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isMessagingAppDataPath(mount.source)) {
      findings.push(
        finding(
          'CRG075',
          `${serviceName} bind-mounts host messaging app data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isCredentialAgentSocketPath(mount.source)) {
      findings.push(
        finding(
          'CRG076',
          `${serviceName} bind-mounts host credential agent socket ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isTaxOrAccountingDataPath(mount.source)) {
      findings.push(
        finding(
          'CRG077',
          `${serviceName} bind-mounts host tax or accounting app data from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
      );
      continue;
    }
    if (isGitOrSshCredentialPath(mount.source)) {
      findings.push(
        finding(
          'CRG034',
          `${serviceName} bind-mounts host Git or SSH credentials from ${mount.source}`,
          filePath,
          lineFor(text, mount.source)
        )
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
    } else if (isServiceNamespace(service[key])) {
      findings.push(finding('CRG023', `${serviceName} uses ${key}: ${service[key]}`, filePath, lineFor(text, key)));
    } else if (isContainerNamespace(service[key])) {
      findings.push(finding('CRG035', `${serviceName} uses ${key}: ${service[key]}`, filePath, lineFor(text, key)));
    }
  }

  for (const key of ['cgroup', 'uts', 'userns_mode']) {
    if (service[key] === 'host') {
      findings.push(finding('CRG013', `${serviceName} uses ${key}: host`, filePath, lineFor(text, key)));
    }
  }

  const addedCapabilities = normalizeCapabilities(service.cap_add);
  for (const capability of addedCapabilities) {
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
  if (addedCapabilities.length > 0 && !dropsAllCapabilities(service.cap_drop)) {
    findings.push(
      finding(
        'CRG022',
        `${serviceName} adds Linux capabilities without cap_drop: [ALL]`,
        filePath,
        lineFor(text, 'cap_add')
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

function dropsAllCapabilities(value) {
  return normalizeCapabilities(value).includes('ALL');
}

function normalizeVolumes(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === 'string') {
      const [source, target, mode = ''] = item.split(':');
      if (
        !target ||
        (!source.startsWith('/') &&
          !isSshAgentSocket(source) &&
          !isDockerClientConfigPath(source) &&
          !isCloudCredentialPath(source) &&
          !isKubernetesCredentialPath(source) &&
          !isPackageManagerCredentialPath(source) &&
          !isBuildToolCredentialPath(source) &&
          !isDotenvCredentialPath(source) &&
          !isShellHistoryPath(source) &&
          !isPasswordStorePath(source) &&
          !isTerraformStateOrCredentialPath(source) &&
          !isSecretManagementKeyPath(source) &&
          !isCryptoWalletKeyPath(source) &&
          !isAiProviderCredentialPath(source) &&
          !isBrowserProfilePath(source) &&
          !isDatabaseClientCredentialPath(source) &&
          !isBackupOrSyncCredentialPath(source) &&
          !isContainerRegistryCredentialPath(source) &&
          !isTunnelOrProxyCredentialPath(source) &&
          !isDeploymentPlatformCredentialPath(source) &&
          !isObservabilityCredentialPath(source) &&
          !isPaymentProcessorCredentialPath(source) &&
          !isCollaborationAppCredentialPath(source) &&
          !isEmailClientCredentialPath(source) &&
          !isPasswordManagerCredentialPath(source) &&
          !isLocalLlmRuntimePath(source) &&
          !isApiClientCredentialPath(source) &&
          !isCiCdCredentialPath(source) &&
          !isCertificateAuthorityKeyPath(source) &&
          !isSecretManagerCredentialPath(source) &&
          !isShellStartupPath(source) &&
          !isEditorOrIdeStatePath(source) &&
          !isTerminalEmulatorStatePath(source) &&
          !isNotesOrKnowledgeBasePath(source) &&
          !isOsKeychainPath(source) &&
          !isHardwareAuthenticatorOrPasskeyPath(source) &&
          !isBrowserAutomationStatePath(source) &&
          !isPrivateSyncIdentityPath(source) &&
          !isRemoteAccessCredentialPath(source) &&
          !isLanguageRuntimePackageCachePath(source) &&
          !isMobileSigningCredentialPath(source) &&
          !isVpnClientProfilePath(source) &&
          !isArtifactSigningCredentialPath(source) &&
          !isCalendarOrContactDataPath(source) &&
          !isMessagingAppDataPath(source) &&
          !isCredentialAgentSocketPath(source) &&
          !isTaxOrAccountingDataPath(source) &&
          !isGitOrSshCredentialPath(source))
      ) {
        return [];
      }
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

function scanBuildContext(service, serviceName, filePath, rootDir, text) {
  const context = buildContext(service.build);
  if (!context || isRemoteBuildContext(context) || substitutionPattern.test(context)) return [];
  const resolved = path.resolve(path.dirname(filePath), context);
  if (isSubpath(rootDir, resolved)) return [];
  return [
    finding(
      'CRG027',
      `${serviceName} build context ${context} is outside the scanned project`,
      filePath,
      lineFor(text, 'context:')
    )
  ];
}

function buildContext(value) {
  if (typeof value === 'string') return value.trim();
  if (value && typeof value === 'object' && typeof value.context === 'string') return value.context.trim();
  return '';
}

function isRemoteBuildContext(value) {
  return /^(https?:\/\/|git@|ssh:\/\/)/i.test(value);
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

function scanDevices(service, serviceName, filePath, text) {
  return normalizeDevices(service.devices)
    .filter((device) => isSensitiveDevice(device.source))
    .map((device) =>
      finding(
        'CRG014',
        `${serviceName} maps sensitive host device ${device.source}`,
        filePath,
        lineFor(text, device.raw)
      )
    );
}

function scanExtraHosts(service, serviceName, filePath, text) {
  return normalizeExtraHosts(service.extra_hosts)
    .filter((entry) => entry.address.toLowerCase() === 'host-gateway')
    .map((entry) =>
      finding(
        'CRG015',
        `${serviceName} maps ${entry.host} to the Docker host gateway`,
        filePath,
        lineFor(text, entry.raw)
      )
    );
}

function scanSysctls(service, serviceName, filePath, text) {
  return normalizeSysctls(service.sysctls)
    .filter((entry) => isRiskySysctl(entry.key, entry.value))
    .map((entry) =>
      finding(
        'CRG017',
        `${serviceName} sets high-risk sysctl ${entry.key}=${entry.value}`,
        filePath,
        lineFor(text, entry.raw)
      )
    );
}

function scanHealthcheck(service, serviceName, filePath, text) {
  if (!service.healthcheck || typeof service.healthcheck !== 'object') return [];
  if (service.healthcheck.disable !== true) return [];
  return [
    finding(
      'CRG018',
      `${serviceName} disables its container healthcheck`,
      filePath,
      lineFor(text, 'disable:')
    )
  ];
}

function scanLogging(service, serviceName, filePath, text) {
  if (!service.logging || typeof service.logging !== 'object') return [];
  if (String(service.logging.driver || '').trim().toLowerCase() !== 'none') return [];
  return [
    finding(
      'CRG019',
      `${serviceName} disables container logging with logging.driver: none`,
      filePath,
      lineFor(text, 'driver:')
    )
  ];
}

function scanReadOnlyRootFs(service, serviceName, filePath, text) {
  if (service.read_only !== false) return [];
  return [
    finding(
      'CRG024',
      `${serviceName} explicitly disables a read-only root filesystem with read_only: false`,
      filePath,
      lineFor(text, 'read_only:')
    )
  ];
}

function scanLabels(service, serviceName, filePath, text) {
  return normalizeLabels(service.labels)
    .filter(([key, value]) => isSecretLiteral(key, value))
    .map(([key]) =>
      finding(
        'CRG025',
        `${serviceName} sets secret-like label ${key} with a literal value`,
        filePath,
        lineFor(text, key)
      )
    );
}

function normalizeLabels(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => {
      if (typeof item !== 'string') return [];
      const [key, ...rest] = item.split('=');
      return [[key, rest.join('=')]];
    });
  }
  if (typeof value === 'object') return Object.entries(value);
  return [];
}

function normalizeDevices(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === 'string') {
      const [source] = item.split(':');
      return source ? [{ source, raw: item }] : [];
    }
    if (!item || typeof item !== 'object') return [];
    const source = item.source || item.path || item.host_path || item.hostPath || '';
    return source ? [{ source: String(source), raw: String(source) }] : [];
  });
}

function normalizeExtraHosts(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => {
      if (typeof item !== 'string') return [];
      const separator = item.includes('=') ? '=' : ':';
      const [host, ...rest] = item.split(separator);
      const address = rest.join(separator).trim();
      if (!host || !address) return [];
      return [{ host: host.trim(), address, raw: item }];
    });
  }
  if (typeof value === 'object') {
    return Object.entries(value).map(([host, address]) => ({
      host,
      address: String(address).trim(),
      raw: String(host)
    }));
  }
  return [];
}

function normalizeSysctls(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => {
      if (typeof item !== 'string') return [];
      const [key, ...rest] = item.split('=');
      const value = rest.join('=');
      if (!key || !value) return [];
      return [{ key: key.trim(), value: value.trim().toLowerCase(), raw: item }];
    });
  }
  if (typeof value === 'object') {
    return Object.entries(value).map(([key, value]) => ({
      key: String(key).trim(),
      value: String(value).trim().toLowerCase(),
      raw: String(key)
    }));
  }
  return [];
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

function isInsecureTlsEnv(key, value) {
  const normalizedKey = String(key || '').trim().toUpperCase();
  const normalizedValue = String(value ?? '').trim().toLowerCase();
  const check = insecureTlsEnv[normalizedKey];
  return Boolean(check && check(normalizedValue));
}

function isInsecureDockerHostEnv(key, value) {
  if (String(key || '').trim().toUpperCase() !== 'DOCKER_HOST') return false;
  const normalizedValue = String(value ?? '').trim().toLowerCase();
  if (!normalizedValue.startsWith('tcp://')) return false;
  if (substitutionPattern.test(normalizedValue)) return false;
  return normalizedValue.includes(':2375') || !normalizedValue.includes(':2376');
}

function isRiskySysctl(key, value) {
  const normalizedKey = String(key || '').trim().toLowerCase();
  const normalizedValue = String(value ?? '').trim().toLowerCase();
  const check = riskySysctls[normalizedKey];
  return Boolean(check && check(normalizedValue));
}

function isTruthyString(value) {
  return value === '1' || value === 'true' || value === 'yes';
}

function isFalseyString(value) {
  return value === '0' || value === 'false' || value === 'no';
}

function isServiceNamespace(value) {
  return typeof value === 'string' && value.trim().toLowerCase().startsWith('service:');
}

function isContainerNamespace(value) {
  return typeof value === 'string' && value.trim().toLowerCase().startsWith('container:');
}

function isSensitiveHostPath(source) {
  return sensitiveHostPaths.some((candidate) => source === candidate || source.startsWith(`${candidate}/`));
}

function isSensitiveDevice(source) {
  return sensitiveDevices.some((candidate) => source === candidate || source.startsWith(`${candidate}/`));
}

function isContainerRuntimeSocket(source) {
  return containerRuntimeSockets.includes(source);
}

function isSshAgentSocket(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const upper = normalized.toUpperCase();
  if (upper.includes('SSH_AUTH_SOCK')) return true;
  return (
    sshAgentSockets.includes(normalized) ||
    /^\/tmp\/ssh-[^/]+\/agent\.\d+$/.test(normalized) ||
    /^\/run\/user\/\d+\/keyring\/ssh$/.test(normalized)
  );
}

function isDockerClientConfigPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  return (
    normalized === '~/.docker' ||
    normalized.startsWith('~/.docker/') ||
    normalized === '$HOME/.docker' ||
    normalized.startsWith('$HOME/.docker/') ||
    normalized === '${HOME}/.docker' ||
    normalized.startsWith('${HOME}/.docker/') ||
    /^\/home\/[^/]+\/\.docker(\/|$)/.test(normalized) ||
    /^\/root\/\.docker(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.docker(\/|$)/.test(normalized)
  );
}

function isCloudCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const prefixes = [
    '~/.aws',
    '$HOME/.aws',
    '${HOME}/.aws',
    '~/.azure',
    '$HOME/.azure',
    '${HOME}/.azure',
    '~/.config/gcloud',
    '$HOME/.config/gcloud',
    '${HOME}/.config/gcloud'
  ];
  return (
    prefixes.some((prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`)) ||
    /^\/home\/[^/]+\/\.(aws|azure)(\/|$)/.test(normalized) ||
    /^\/root\/\.(aws|azure)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.(aws|azure)(\/|$)/.test(normalized) ||
    /^\/home\/[^/]+\/\.config\/gcloud(\/|$)/.test(normalized) ||
    /^\/root\/\.config\/gcloud(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.config\/gcloud(\/|$)/.test(normalized)
  );
}

function isKubernetesCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const prefixes = [
    '~/.kube',
    '$HOME/.kube',
    '${HOME}/.kube'
  ];
  return (
    prefixes.some((prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`)) ||
    /^\/home\/[^/]+\/\.kube(\/|$)/.test(normalized) ||
    /^\/root\/\.kube(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.kube(\/|$)/.test(normalized)
  );
}

function isPackageManagerCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homeFiles = ['.npmrc', '.pypirc', '.gem/credentials', '.cargo/credentials', '.netrc'];
  return (
    homePrefixes.some((home) =>
      homeFiles.some((file) => normalized === `${home}/${file}` || normalized.startsWith(`${home}/${file}/`))
    ) ||
    /^\/home\/[^/]+\/(\.npmrc|\.pypirc|\.gem\/credentials|\.cargo\/credentials|\.netrc)(\/|$)/.test(normalized) ||
    /^\/root\/(\.npmrc|\.pypirc|\.gem\/credentials|\.cargo\/credentials|\.netrc)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.npmrc|\.pypirc|\.gem\/credentials|\.cargo\/credentials|\.netrc)(\/|$)/.test(normalized)
  );
}

function isBuildToolCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.m2/settings.xml',
    '.gradle/gradle.properties',
    '.sbt/.credentials',
    '.nuget/NuGet/NuGet.Config',
    '.config/NuGet/NuGet.Config',
    '.composer/auth.json'
  ];
  const linuxPattern = /(\.m2\/settings\.xml|\.gradle\/gradle\.properties|\.sbt\/\.credentials|\.nuget\/NuGet\/NuGet\.Config|\.config\/NuGet\/NuGet\.Config|\.composer\/auth\.json)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${linuxPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${linuxPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${linuxPattern.source}`).test(normalized)
  );
}

function isDotenvCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  return /^\.env([.-][^/]*)?$|^\.envrc$/.test(path.basename(normalized));
}

function isShellHistoryPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const historyFiles = [
    '.ash_history',
    '.bash_history',
    '.fish_history',
    '.mysql_history',
    '.node_repl_history',
    '.psql_history',
    '.python_history',
    '.rediscli_history',
    '.sqlite_history',
    '.zsh_history'
  ];
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  return (
    homePrefixes.some((home) =>
      historyFiles.some((file) => normalized === `${home}/${file}` || normalized.startsWith(`${home}/${file}/`))
    ) ||
    /^\/home\/[^/]+\/\.(ash|bash|fish|mysql|psql|python|rediscli|sqlite|zsh)_history(\/|$)/.test(normalized) ||
    /^\/home\/[^/]+\/\.node_repl_history(\/|$)/.test(normalized) ||
    /^\/root\/\.(ash|bash|fish|mysql|psql|python|rediscli|sqlite|zsh)_history(\/|$)/.test(normalized) ||
    /^\/root\/\.node_repl_history(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.(ash|bash|fish|mysql|psql|python|rediscli|sqlite|zsh)_history(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.node_repl_history(\/|$)/.test(normalized)
  );
}

function isPasswordStorePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.gnupg',
    '.password-store',
    '.local/share/password-store',
    '.local/share/gnupg',
    '.config/gopass',
    '.config/1Password'
  ];
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/(\.gnupg|\.password-store|\.local\/share\/(password-store|gnupg)|\.config\/(gopass|1Password))(\/|$)/.test(normalized) ||
    /^\/root\/(\.gnupg|\.password-store|\.local\/share\/(password-store|gnupg)|\.config\/(gopass|1Password))(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.gnupg|\.password-store|\.local\/share\/(password-store|gnupg)|\.config\/(gopass|1Password))(\/|$)/.test(normalized)
  );
}

function isTerraformStateOrCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = ['.terraform.d', '.tofu.d', '.terraformrc', '.tofurc'];
  const basename = path.basename(normalized);
  return (
    basename === 'terraform.tfstate' ||
    basename === 'terraform.tfstate.backup' ||
    basename === 'tofu.tfstate' ||
    basename === 'tofu.tfstate.backup' ||
    basename.endsWith('.tfstate') ||
    basename.endsWith('.tfstate.backup') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/(\.terraform\.d|\.tofu\.d|\.terraformrc|\.tofurc)(\/|$)/.test(normalized) ||
    /^\/root\/(\.terraform\.d|\.tofu\.d|\.terraformrc|\.tofurc)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.terraform\.d|\.tofu\.d|\.terraformrc|\.tofurc)(\/|$)/.test(normalized)
  );
}

function isSecretManagementKeyPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.age-key.txt',
    '.config/age/keys.txt',
    '.config/sops/age/keys.txt',
    '.sops/age/keys.txt'
  ];
  const keyPattern = /(\.age-key\.txt|\.config\/age\/keys\.txt|\.config\/sops\/age\/keys\.txt|\.sops\/age\/keys\.txt)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isCryptoWalletKeyPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.bitcoin/wallet.dat',
    '.config/solana/id.json',
    '.ethereum/keystore',
    '.foundry/keystores',
    '.near-credentials'
  ];
  const keyPattern = /(\.bitcoin\/wallet\.dat|\.config\/solana\/id\.json|\.ethereum\/keystore|\.foundry\/keystores|\.near-credentials)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isAiProviderCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.anthropic',
    '.claude',
    '.claude.json',
    '.codex',
    '.cursor',
    '.gemini',
    '.openai',
    '.config/anthropic',
    '.config/claude',
    '.config/Cursor',
    '.config/gemini',
    '.config/openai'
  ];
  const keyPattern = /(\.anthropic|\.claude|\.claude\.json|\.codex|\.cursor|\.gemini|\.openai|\.config\/(anthropic|claude|Cursor|cursor|gemini|openai))(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isBrowserProfilePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/google-chrome',
    '.config/chromium',
    '.config/BraveSoftware',
    '.config/microsoft-edge',
    '.mozilla/firefox',
    'Library/Application Support/Google/Chrome',
    'Library/Application Support/Chromium',
    'Library/Application Support/BraveSoftware',
    'Library/Application Support/Microsoft Edge',
    'Library/Application Support/Firefox'
  ];
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)(\/|$)/.test(normalized) ||
    /^\/home\/[^/]+\/\.mozilla\/firefox(\/|$)/.test(normalized) ||
    /^\/root\/\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)(\/|$)/.test(normalized) ||
    /^\/root\/\.mozilla\/firefox(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Google\/Chrome|Chromium|BraveSoftware|Microsoft Edge|Firefox)(\/|$)/.test(normalized)
  );
}

function isDatabaseClientCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.pgpass',
    '.pg_service.conf',
    '.my.cnf',
    '.mylogin.cnf',
    '.mongorc.js',
    '.dbshell',
    '.duckdbrc'
  ];
  const keyPattern = /(\.pgpass|\.pg_service\.conf|\.my\.cnf|\.mylogin\.cnf|\.mongorc\.js|\.dbshell|\.duckdbrc)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isBackupOrSyncCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/rclone/rclone.conf',
    '.config/restic',
    '.restic',
    '.borg',
    '.config/borg'
  ];
  const keyPattern = /(\.config\/rclone\/rclone\.conf|\.config\/restic|\.restic|\.borg|\.config\/borg)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isContainerRegistryCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/containers/auth.json',
    '.config/containers/certs.d',
    '.local/share/containers/auth.json'
  ];
  const keyPattern = /(\.config\/containers\/(auth\.json|certs\.d)|\.local\/share\/containers\/auth\.json)(\/|$)/;
  return (
    normalized === '/etc/containers/auth.json' ||
    normalized.startsWith('/etc/containers/certs.d/') ||
    normalized === '/etc/containers/certs.d' ||
    normalized.startsWith('/etc/docker/certs.d/') ||
    normalized === '/etc/docker/certs.d' ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isTunnelOrProxyCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.ngrok2/ngrok.yml',
    '.config/ngrok/ngrok.yml',
    '.cloudflared',
    '.config/cloudflared',
    '.tailscale',
    '.config/tailscale',
    '.config/zerotier'
  ];
  const keyPattern = /(\.ngrok2\/ngrok\.yml|\.config\/ngrok\/ngrok\.yml|\.cloudflared|\.config\/cloudflared|\.tailscale|\.config\/tailscale|\.config\/zerotier)(\/|$)/;
  return (
    normalized === '/etc/cloudflared' ||
    normalized.startsWith('/etc/cloudflared/') ||
    normalized === '/var/lib/tailscale' ||
    normalized.startsWith('/var/lib/tailscale/') ||
    normalized === '/var/lib/zerotier-one' ||
    normalized.startsWith('/var/lib/zerotier-one/') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isDeploymentPlatformCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.vercel',
    '.netlify',
    '.render',
    '.fly',
    '.config/fly',
    '.railway',
    '.config/railway'
  ];
  const keyPattern = /(\.vercel|\.netlify|\.render|\.fly|\.config\/fly|\.railway|\.config\/railway)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isObservabilityCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.datadog',
    '.config/datadog',
    '.sentryclirc',
    '.config/sentry',
    '.newrelic',
    '.config/newrelic',
    '.config/honeycomb',
    '.config/grafana'
  ];
  const keyPattern = /(\.datadog|\.config\/datadog|\.sentryclirc|\.config\/sentry|\.newrelic|\.config\/newrelic|\.config\/honeycomb|\.config\/grafana)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isPaymentProcessorCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.stripe',
    '.config/stripe',
    '.config/razorpay',
    '.config/paddle',
    '.config/lemonsqueezy',
    '.config/square'
  ];
  const keyPattern = /(\.stripe|\.config\/(stripe|razorpay|paddle|lemonsqueezy|square))(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isCollaborationAppCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/slack',
    '.config/discord',
    '.config/teams',
    '.config/zoom',
    '.mattermost',
    'Library/Application Support/Slack',
    'Library/Application Support/discord',
    'Library/Application Support/Microsoft/Teams',
    'Library/Application Support/zoom.us'
  ];
  const keyPattern = /(\.config\/(slack|discord|teams|zoom)|\.mattermost)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Slack|discord|Microsoft\/Teams|zoom\.us)(\/|$)/.test(normalized)
  );
}

function isEmailClientCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.thunderbird',
    '.config/aerc',
    '.config/neomutt',
    '.mutt',
    '.msmtprc',
    '.mbsyncrc',
    '.offlineimaprc',
    'Library/Mail',
    'Library/Accounts',
    'Library/Thunderbird'
  ];
  const keyPattern = /(\.thunderbird|\.config\/(aerc|neomutt)|\.mutt|\.msmtprc|\.mbsyncrc|\.offlineimaprc)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/(Mail|Accounts|Thunderbird)(\/|$)/.test(normalized)
  );
}

function isPasswordManagerCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/Bitwarden',
    '.config/Bitwarden CLI',
    '.config/bitwarden',
    '.config/keepassxc',
    '.local/share/keepassxc',
    'Library/Application Support/Bitwarden',
    'Library/Application Support/Bitwarden CLI',
    'Library/Application Support/KeePassXC'
  ];
  const keyPattern = /(\.config\/(Bitwarden|Bitwarden CLI|bitwarden|keepassxc)|\.local\/share\/keepassxc)(\/|$)/;
  return (
    path.basename(normalized).endsWith('.kdbx') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Bitwarden|Bitwarden CLI|KeePassXC)(\/|$)/.test(normalized)
  );
}

function isLocalLlmRuntimePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.ollama',
    '.lmstudio',
    '.cache/lm-studio',
    '.cache/huggingface/hub',
    '.cache/llama.cpp',
    '.config/Jan',
    'Library/Application Support/Ollama',
    'Library/Application Support/LM Studio',
    'Library/Application Support/Jan'
  ];
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/(\.ollama|\.lmstudio|\.cache\/(lm-studio|llama\.cpp)|\.cache\/huggingface\/hub|\.config\/Jan)(\/|$)/.test(normalized) ||
    /^\/root\/(\.ollama|\.lmstudio|\.cache\/(lm-studio|llama\.cpp)|\.cache\/huggingface\/hub|\.config\/Jan)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.ollama|\.lmstudio|\.cache\/(lm-studio|llama\.cpp)|\.cache\/huggingface\/hub|\.config\/Jan)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Ollama|LM Studio|Jan)(\/|$)/.test(normalized)
  );
}

function isApiClientCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/httpie',
    '.config/postman',
    '.config/Insomnia',
    '.config/insomnia',
    '.insomnia',
    '.bruno',
    '.hoppscotch',
    '.curlrc',
    '.wgetrc'
  ];
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/\.config\/(httpie|postman|Insomnia|insomnia)(\/|$)/.test(normalized) ||
    /^\/home\/[^/]+\/(\.insomnia|\.bruno|\.hoppscotch|\.curlrc|\.wgetrc)(\/|$)/.test(normalized) ||
    /^\/root\/\.config\/(httpie|postman|Insomnia|insomnia)(\/|$)/.test(normalized) ||
    /^\/root\/(\.insomnia|\.bruno|\.hoppscotch|\.curlrc|\.wgetrc)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/\.config\/(httpie|postman|Insomnia|insomnia)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.insomnia|\.bruno|\.hoppscotch|\.curlrc|\.wgetrc)(\/|$)/.test(normalized)
  );
}

function isCiCdCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.circleci',
    '.config/circleci',
    '.buildkite',
    '.config/buildkite',
    '.travis',
    '.travis.yml',
    '.config/glab-cli',
    '.config/drone',
    '.config/jenkins',
    '.jenkins'
  ];
  const keyPattern = /(\.circleci|\.config\/circleci|\.buildkite|\.config\/buildkite|\.travis|\.travis\.yml|\.config\/(glab-cli|drone|jenkins)|\.jenkins)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isCertificateAuthorityKeyPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.step',
    '.config/step',
    '.cfssl',
    '.config/cfssl',
    '.local/share/mkcert',
    '.minica',
    'Library/Application Support/mkcert',
    'Library/Application Support/Smallstep'
  ];
  const keyPattern = /(\.step|\.config\/step|\.cfssl|\.config\/cfssl|\.local\/share\/mkcert|\.minica)(\/|$)/;
  return (
    normalized === '/etc/ssl/private' ||
    normalized.startsWith('/etc/ssl/private/') ||
    normalized === '/etc/pki/private' ||
    normalized.startsWith('/etc/pki/private/') ||
    normalized === '/etc/step' ||
    normalized.startsWith('/etc/step/') ||
    normalized === '/var/lib/step' ||
    normalized.startsWith('/var/lib/step/') ||
    path.basename(normalized) === 'root_ca_key.pem' ||
    path.basename(normalized) === 'intermediate_ca_key.pem' ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(mkcert|Smallstep)(\/|$)/.test(normalized)
  );
}

function isSecretManagerCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.vault-token',
    '.config/vault',
    '.config/op',
    '.op',
    '.config/doppler',
    '.config/infisical',
    '.akeyless'
  ];
  const keyPattern = /(\.vault-token|\.config\/(vault|op|doppler|infisical)|\.op|\.akeyless)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isShellStartupPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.bash_profile',
    '.bashrc',
    '.config/fish/config.fish',
    '.profile',
    '.zprofile',
    '.zshenv',
    '.zshrc'
  ];
  const keyPattern = /(\.bash_profile|\.bashrc|\.config\/fish\/config\.fish|\.profile|\.zprofile|\.zshenv|\.zshrc)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isEditorOrIdeStatePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.vscode',
    '.config/Code',
    '.config/VSCodium',
    '.config/JetBrains',
    '.config/zed',
    'Library/Application Support/Code',
    'Library/Application Support/VSCodium',
    'Library/Application Support/JetBrains',
    'Library/Application Support/Zed'
  ];
  const keyPattern = /(\.vscode|\.config\/(Code|VSCodium|JetBrains|zed))(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/(\.vscode|\.config\/(Code|VSCodium|JetBrains|zed))(\/|$)/.test(normalized) ||
    /^\/root\/(\.vscode|\.config\/(Code|VSCodium|JetBrains|zed))(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.vscode|\.config\/(Code|VSCodium|JetBrains|zed))(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Code|VSCodium|JetBrains|Zed)(\/|$)/.test(normalized)
  );
}

function isTerminalEmulatorStatePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/alacritty',
    '.config/ghostty',
    '.config/kitty',
    '.config/terminator',
    '.config/wezterm',
    '.warp',
    'Library/Application Support/com.mitchellh.ghostty',
    'Library/Application Support/iTerm2',
    'Library/Application Support/Warp'
  ];
  const keyPattern = /(\.config\/(alacritty|ghostty|kitty|terminator|wezterm)|\.warp)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(com\.mitchellh\.ghostty|iTerm2|Warp)(\/|$)/.test(normalized)
  );
}

function isNotesOrKnowledgeBasePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/joplin',
    '.config/joplin-desktop',
    '.config/logseq',
    '.logseq',
    'Library/Application Support/Joplin',
    'Library/Application Support/logseq',
    'Library/Application Support/Notion',
    'Library/Group Containers/group.com.apple.notes'
  ];
  const keyPattern = /(\.config\/(joplin|joplin-desktop|logseq)|\.logseq)(\/|$)/;
  return (
    normalized.endsWith('/.obsidian') ||
    normalized.includes('/.obsidian/') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Joplin|logseq|Notion)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Group Containers\/group\.com\.apple\.notes(\/|$)/.test(normalized)
  );
}

function isOsKeychainPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.gnome2/keyrings',
    '.local/share/keyrings',
    '.config/kwalletd',
    '.local/share/kwalletd',
    'Library/Keychains'
  ];
  const keyPattern = /(\.gnome2\/keyrings|\.local\/share\/keyrings|\.config\/kwalletd|\.local\/share\/kwalletd)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Keychains(\/|$)/.test(normalized)
  );
}

function isHardwareAuthenticatorOrPasskeyPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/Yubico',
    '.config/yubico',
    '.yubico',
    '.config/libfido2',
    '.local/share/webauthn',
    'Library/Application Support/Yubico',
    'Library/Application Support/WebAuthn'
  ];
  const keyPattern = /(\.config\/(Yubico|yubico|libfido2)|\.yubico|\.local\/share\/webauthn)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Yubico|WebAuthn)(\/|$)/.test(normalized)
  );
}

function isBrowserAutomationStatePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.cache/ms-playwright',
    '.cache/puppeteer',
    '.cache/Cypress',
    '.config/cypress',
    '.config/selenium',
    '.wdio',
    '.webdriverio',
    'Library/Caches/ms-playwright',
    'Library/Caches/puppeteer',
    'Library/Caches/Cypress',
    'Library/Application Support/Cypress',
    'Library/Application Support/selenium'
  ];
  const keyPattern = /(\.cache\/(ms-playwright|puppeteer|Cypress)|\.config\/(cypress|selenium)|\.wdio|\.webdriverio)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Caches\/(ms-playwright|puppeteer|Cypress)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Cypress|selenium)(\/|$)/.test(normalized)
  );
}

function isPrivateSyncIdentityPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/syncthing',
    '.local/state/syncthing',
    '.config/resilio-sync',
    '.config/Sync',
    'Library/Application Support/Syncthing',
    'Library/Application Support/Resilio Sync'
  ];
  const keyPattern = /(\.config\/(syncthing|resilio-sync|Sync)|\.local\/state\/syncthing)(\/|$)/;
  return (
    normalized === '/var/lib/syncthing' ||
    normalized.startsWith('/var/lib/syncthing/') ||
    normalized === '/var/lib/resilio-sync' ||
    normalized.startsWith('/var/lib/resilio-sync/') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Syncthing|Resilio Sync)(\/|$)/.test(normalized)
  );
}

function isRemoteAccessCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.anydesk',
    '.config/AnyDesk',
    '.config/teamviewer',
    '.config/rustdesk',
    'Library/Application Support/AnyDesk',
    'Library/Application Support/TeamViewer',
    'Library/Application Support/RustDesk'
  ];
  const keyPattern = /(\.anydesk|\.config\/(AnyDesk|anydesk|teamviewer|rustdesk))(\/|$)/;
  return (
    normalized === '/etc/anydesk' ||
    normalized.startsWith('/etc/anydesk/') ||
    normalized === '/etc/teamviewer' ||
    normalized.startsWith('/etc/teamviewer/') ||
    normalized === '/var/lib/anydesk' ||
    normalized.startsWith('/var/lib/anydesk/') ||
    normalized === '/var/lib/teamviewer' ||
    normalized.startsWith('/var/lib/teamviewer/') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(AnyDesk|TeamViewer|RustDesk)(\/|$)/.test(normalized)
  );
}

function isLanguageRuntimePackageCachePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.npm',
    '.cache/pip',
    '.cache/pypoetry',
    '.cache/yarn',
    '.cache/pnpm',
    '.cargo/registry',
    '.cargo/git',
    '.local/share/pnpm',
    'Library/Caches/pip',
    'Library/Caches/pypoetry',
    'Library/Caches/Yarn',
    'Library/pnpm'
  ];
  const keyPattern = /(\.npm|\.cache\/(pip|pypoetry|yarn|pnpm)|\.cargo\/(registry|git)|\.local\/share\/pnpm)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Caches\/(pip|pypoetry|Yarn)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/pnpm(\/|$)/.test(normalized)
  );
}

function isMobileSigningCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.android/debug.keystore',
    '.android/release.keystore',
    '.appstoreconnect/private_keys',
    'Library/MobileDevice/Provisioning Profiles',
    'Library/Developer/Xcode/UserData/Provisioning Profiles'
  ];
  const keyPattern = /(\.android\/(debug|release)\.keystore|\.appstoreconnect\/private_keys)(\/|$)/;
  return (
    path.basename(normalized).endsWith('.keystore') ||
    path.basename(normalized).endsWith('.jks') ||
    path.basename(normalized).endsWith('.mobileprovision') ||
    path.basename(normalized).endsWith('.p12') ||
    path.basename(normalized).startsWith('AuthKey_') ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/MobileDevice\/Provisioning Profiles(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Developer\/Xcode\/UserData\/Provisioning Profiles(\/|$)/.test(normalized)
  );
}

function isVpnClientProfilePath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/wireguard',
    '.config/openvpn',
    '.openvpn',
    'Library/Application Support/Tunnelblick',
    'Library/Application Support/Viscosity'
  ];
  const keyPattern = /(\.config\/(wireguard|openvpn)|\.openvpn)(\/|$)/;
  return (
    normalized === '/etc/wireguard' ||
    normalized.startsWith('/etc/wireguard/') ||
    normalized === '/etc/openvpn' ||
    normalized.startsWith('/etc/openvpn/') ||
    path.basename(normalized).endsWith('.ovpn') ||
    (path.basename(normalized).endsWith('.conf') && normalized.includes('/wireguard/')) ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(Tunnelblick|Viscosity)(\/|$)/.test(normalized)
  );
}

function isArtifactSigningCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.sigstore',
    '.cosign',
    '.config/sigstore',
    '.config/cosign',
    '.config/notation',
    '.config/notary',
    '.local/share/notation',
    '.notary'
  ];
  const keyPattern = /(\.sigstore|\.cosign|\.config\/(sigstore|cosign|notation|notary)|\.local\/share\/notation|\.notary)(\/|$)/;
  return (
    path.basename(normalized) === 'cosign.key' ||
    path.basename(normalized) === 'minisign.key' ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized)
  );
}

function isCalendarOrContactDataPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/khal',
    '.config/vdirsyncer',
    '.local/share/evolution',
    '.local/share/gnome-calendar',
    'Library/Application Support/AddressBook',
    'Library/Calendars'
  ];
  const keyPattern = /(\.config\/(khal|vdirsyncer)|\.local\/share\/(evolution|gnome-calendar))(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/(Calendars|Application Support\/AddressBook)(\/|$)/.test(normalized)
  );
}

function isMessagingAppDataPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/Signal',
    '.config/Element',
    '.local/share/TelegramDesktop',
    '.local/share/TelegramDesktop/tdata',
    'Library/Application Support/Signal',
    'Library/Application Support/Telegram Desktop',
    'Library/Messages'
  ];
  const keyPattern = /(\.config\/(Signal|Element)|\.local\/share\/TelegramDesktop)(\/|$)/;
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/(Messages|Application Support\/(Signal|Telegram Desktop))(\/|$)/.test(normalized)
  );
}

function isCredentialAgentSocketPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const basename = path.basename(normalized);
  return (
    /^S\.gpg-agent(\..+)?$/.test(basename) ||
    /^gpg-agent(\..+)?\.sock$/.test(basename) ||
    basename === 'pinentry' ||
    /^\/run\/user\/\d+\/gnupg\/S\.gpg-agent(\..+)?$/.test(normalized) ||
    /^\/run\/user\/\d+\/keyring\/(control|pkcs11|secrets)$/.test(normalized) ||
    /^\/run\/user\/\d+\/bus$/.test(normalized)
  );
}

function isTaxOrAccountingDataPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = [
    '.config/gnucash',
    '.local/share/gnucash',
    '.local/share/GnuCash',
    'Documents/TurboTax',
    'Documents/TaxAct',
    'Documents/H&R Block',
    'Library/Application Support/GnuCash',
    'Library/Application Support/Quicken',
    'Library/Application Support/QuickBooks'
  ];
  const keyPattern = /(\.config\/gnucash|\.local\/share\/(gnucash|GnuCash)|Documents\/(TurboTax|TaxAct|H&R Block))(\/|$)/;
  return (
    /\.(tax\d{2}|tax20\d{2}|qdf|qbb|qbw|gnucash)$/i.test(path.basename(normalized)) ||
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    new RegExp(`^/home/[^/]+/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/root/${keyPattern.source}`).test(normalized) ||
    new RegExp(`^/Users/[^/]+/${keyPattern.source}`).test(normalized) ||
    /^\/Users\/[^/]+\/Library\/Application Support\/(GnuCash|Quicken|QuickBooks)(\/|$)/.test(normalized)
  );
}

function isGitOrSshCredentialPath(source) {
  const normalized = String(source || '').trim();
  if (!normalized) return false;
  const homePrefixes = ['~', '$HOME', '${HOME}'];
  const homePaths = ['.gitconfig', '.git-credentials', '.config/gh', '.config/hub', '.ssh'];
  return (
    homePrefixes.some((home) =>
      homePaths.some((item) => normalized === `${home}/${item}` || normalized.startsWith(`${home}/${item}/`))
    ) ||
    /^\/home\/[^/]+\/(\.gitconfig|\.git-credentials|\.config\/(gh|hub)|\.ssh)(\/|$)/.test(normalized) ||
    /^\/root\/(\.gitconfig|\.git-credentials|\.config\/(gh|hub)|\.ssh)(\/|$)/.test(normalized) ||
    /^\/Users\/[^/]+\/(\.gitconfig|\.git-credentials|\.config\/(gh|hub)|\.ssh)(\/|$)/.test(normalized)
  );
}

function isSubpath(rootDir, targetPath) {
  const relative = path.relative(path.resolve(rootDir), path.resolve(targetPath));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
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
