'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('./config');
const { exactSignatures, regexSignatures } = require('./signatures');

const defaultRoots = ['backend-go', 'backend', 'frontend', 'desktop', 'packages', 'scripts', '.github', '.vscode'];
const defaultIgnoredDirectories = new Set([
  '.angular',
  '.git',
  '.next',
  '.nuxt',
  '.omx',
  '.pytest_cache',
  '.turbo',
  'bin',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'out',
  'playwright-report',
  'target',
  'test-results',
  'vendor',
  'visual-checks',
]);
const defaultSkippedFileNames = new Set([
  'security-malware-guard.cjs',
  'security-guardrails.js',
  'malware_guard_test.go',
]);
const executableExtensions = new Set(['.bat', '.cmd', '.com', '.dll', '.exe', '.scr', '.vbs', '.wsf']);
const maxTextFileBytes = 5 * 1024 * 1024;

function scan(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const loaded = loadConfig(cwd, options.configPath);
  const config = { ...loaded.config, ...(options.config || {}) };
  const roots = normalizeRoots(cwd, options.roots || config.roots);
  const selfPackage = isSecurityGuardrailsPackage(cwd);
  const findings = [];

  for (const root of roots) {
    walk(root, cwd, findings, { ...options, config, selfPackage });
  }

  return {
    cwd,
    configPath: loaded.configPath,
    roots,
    findings,
    ok: findings.length === 0,
  };
}

function normalizeRoots(cwd, roots) {
  const requested = roots && roots.length > 0 ? roots : defaultRoots;
  const resolved = [];
  for (const root of requested) {
    const fullPath = path.resolve(cwd, root);
    if (fs.existsSync(fullPath)) {
      resolved.push(fullPath);
    }
  }
  if (resolved.length === 0) {
    resolved.push(cwd);
  }
  return resolved;
}

function walk(root, cwd, findings, options) {
  if (!fs.existsSync(root)) {
    return;
  }
  const stat = fs.statSync(root);
  if (stat.isFile()) {
    scanFile(root, cwd, findings, options);
    return;
  }

  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDirectory(entry.name, options)) {
        continue;
      }
      walk(fullPath, cwd, findings, options);
      continue;
    }
    if (entry.isFile()) {
      scanFile(fullPath, cwd, findings, options);
    }
  }
}

function scanFile(filePath, cwd, findings, options) {
  const baseName = path.basename(filePath);
  const skipFiles = new Set([...(options.config?.skipFiles || []), ...(options.skipFiles || [])]);
  if (defaultSkippedFileNames.has(baseName) || skipFiles.has(baseName)) {
    return;
  }
  if (options.selfPackage && isSelfPackageFixture(cwd, filePath)) {
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  if (executableExtensions.has(ext)) {
    if (isAllowedExecutable(cwd, filePath, options.config)) {
      return;
    }
    findings.push(finding('executable-artifact-in-source-tree', cwd, filePath, 1, `Executable artifact with ${ext} extension is not allowed in source/build inputs.`));
    return;
  }

  const stat = fs.statSync(filePath);
  if (stat.size > maxTextFileBytes) {
    return;
  }

  const buffer = fs.readFileSync(filePath);
  if (buffer.includes(0)) {
    return;
  }

  const content = buffer.toString('utf8');
  const configuredExactSignatures = [
    ...exactSignatures,
    ...(options.config?.extraSignatures || []).map((signature, index) => [`config-extra-signature-${index + 1}`, signature]),
  ];
  const configuredRegexSignatures = [
    ...regexSignatures,
    ...(options.config?.extraRegexSignatures || []).map((signature, index) => [`config-extra-regex-${index + 1}`, new RegExp(signature)]),
  ];
  for (const [id, signature] of configuredExactSignatures) {
    const index = content.indexOf(signature);
    if (index >= 0) {
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, index), `Matched ${signature}`));
    }
  }

  for (const [id, pattern] of configuredRegexSignatures) {
    const match = pattern.exec(content);
    if (match?.index >= 0) {
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, match.index), `Matched ${pattern}`));
    }
  }

  if (baseName === 'package.json') {
    auditPackageScripts(cwd, filePath, content, findings, options.config);
  }
  if (baseName === 'package-lock.json' || baseName === 'npm-shrinkwrap.json') {
    auditNpmLockfile(cwd, filePath, content, findings);
  }

  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.length < 2000) {
      return;
    }
    if (/String\.fromCharCode\(127\)|global\[[^\]]+\]\s*=\s*require|var\s+_\$_[A-Za-z0-9_]+/.test(line)) {
      findings.push(finding('long-obfuscated-javascript-line', cwd, filePath, index + 1, 'Very long line contains obfuscated JavaScript loader markers.'));
    }
  });
}

function isSecurityGuardrailsPackage(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return false;
  }
  try {
    return JSON.parse(fs.readFileSync(packagePath, 'utf8')).name === 'security-guardrails';
  } catch {
    return false;
  }
}

function isSelfPackageFixture(cwd, filePath) {
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  return rel === 'README.md' ||
    rel === 'lib/signatures.js' ||
    rel === 'skill/security-guardrails/SKILL.md' ||
    rel.startsWith('test/');
}

function isIgnoredDirectory(name, options = {}) {
  if (defaultIgnoredDirectories.has(name) || name.startsWith('target-')) {
    return true;
  }
  return Boolean((options.config?.ignoreDirs || []).includes(name) || (options.ignoreDirs || []).includes(name));
}

function lineNumberFor(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}

function finding(id, cwd, filePath, line, detail) {
  return {
    id,
    file: path.relative(cwd, filePath).replaceAll(path.sep, '/'),
    line,
    detail,
  };
}

function formatFindings(findings) {
  if (findings.length === 0) {
    return '[security-guardrails] OK';
  }
  return [
    '[security-guardrails] Suspicious artifact(s) blocked:',
    ...findings.map((item) => `- ${item.id}: ${item.file}:${item.line} - ${item.detail}`),
  ].join('\n');
}

function isAllowedExecutable(cwd, filePath, config = {}) {
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  return (config.allowExecutables || []).some((allowed) => rel === allowed || rel.endsWith(`/${allowed}`));
}

function auditPackageScripts(cwd, filePath, content, findings, config = {}) {
  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return;
  }
  const scripts = pkg.scripts || {};
  const lifecycleScripts = new Set(['preinstall', 'install', 'postinstall', 'prepare']);
  const suspicious = [
    /\b(?:curl|wget)\b/i,
    /\bpowershell\b|\bInvoke-WebRequest\b|\biwr\b/i,
    /\bnode\s+-e\b/i,
    /\beval\s*\(/i,
    /\b(?:base64|atob|certutil)\b/i,
    /\b(?:bash|sh)\s+-c\b/i,
    /\bchild_process\b/i,
  ];
  for (const [name, command] of Object.entries(scripts)) {
    if (!config.auditAllPackageScripts && !lifecycleScripts.has(name)) {
      continue;
    }
    for (const pattern of suspicious) {
      if (pattern.test(String(command))) {
        findings.push(finding(
          'suspicious-package-script',
          cwd,
          filePath,
          lineNumberFor(content, content.indexOf(`"${name}"`)),
          `Suspicious package script "${name}" matches ${pattern}: ${command}`,
        ));
      }
    }
  }
}

function auditNpmLockfile(cwd, filePath, content, findings) {
  let lockfile;
  try {
    lockfile = JSON.parse(content);
  } catch {
    return;
  }
  const packages = lockfile.packages || {};
  for (const [name, entry] of Object.entries(packages)) {
    const resolved = String(entry?.resolved || '');
    if (resolved.startsWith('http://')) {
      findings.push(finding('insecure-lockfile-url', cwd, filePath, lineNumberFor(content, content.indexOf(resolved)), `Package ${name || '<root>'} resolves over insecure HTTP: ${resolved}`));
    }
    if (/pastebin\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com/i.test(resolved)) {
      findings.push(finding('suspicious-lockfile-url', cwd, filePath, lineNumberFor(content, content.indexOf(resolved)), `Package ${name || '<root>'} resolves from a suspicious host: ${resolved}`));
    }
  }
}

module.exports = {
  defaultRoots,
  scan,
  formatFindings,
};
