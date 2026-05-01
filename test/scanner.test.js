'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { scan } = require('../lib/scanner');
const { formatResult } = require('../lib/output');

test('scan passes on a clean project', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-clean-'));
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'tailwind.config.js'), 'module.exports = { plugins: [] };\n');

  const result = scan({ cwd: root, roots: ['frontend'] });

  assert.equal(result.ok, true);
  assert.deepEqual(result.findings, []);
});

test('scan blocks the known injected loader marker', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-bad-'));
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'tailwind.config.js'), "module.exports = {};\nglobal.i='2-30-4';\n");

  const result = scan({ cwd: root, roots: ['frontend'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'void-dokkaebi-loader-marker');
});

test('scan ignores build output directories', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-ignore-'));
  fs.mkdirSync(path.join(root, 'desktop', 'src-tauri', 'target-release-codex'), { recursive: true });
  fs.writeFileSync(path.join(root, 'desktop', 'src-tauri', 'target-release-codex', 'app.exe'), 'binary');

  const result = scan({ cwd: root, roots: ['desktop'] });

  assert.equal(result.ok, true);
});

test('scan blocks vscode folder-open autostart', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-vscode-'));
  fs.mkdirSync(path.join(root, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vscode', 'tasks.json'), '{"runOn":"folderOpen"}\n');

  const result = scan({ cwd: root, roots: ['.vscode'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'vscode-folder-open-autostart');
});

test('scan honors config allowExecutables and extraSignatures', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-config-'));
  fs.mkdirSync(path.join(root, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(root, '.security-guardrails.json'), JSON.stringify({
    roots: ['tools'],
    allowExecutables: ['tools/known-safe.exe'],
    extraSignatures: ['custom-bad-domain.example'],
  }, null, 2));
  fs.writeFileSync(path.join(root, 'tools', 'known-safe.exe'), 'binary');
  fs.writeFileSync(path.join(root, 'tools', 'config.js'), 'const url = "custom-bad-domain.example";\n');

  const result = scan({ cwd: root });

  assert.equal(result.ok, false);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, 'config-extra-signature-1');
});

test('scan audits suspicious package lifecycle scripts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-package-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      postinstall: 'node -e "console.log(1)"',
    },
  }, null, 2));

  const result = scan({ cwd: root, roots: ['package.json'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'suspicious-package-script');
});

test('scan audits insecure lockfile URLs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-lock-'));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    packages: {
      'node_modules/example': {
        resolved: 'http://registry.npmjs.org/example/-/example-1.0.0.tgz',
      },
    },
  }, null, 2));

  const result = scan({ cwd: root, roots: ['package-lock.json'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'insecure-lockfile-url');
});

test('golden malicious fixture is blocked and clean fixture passes', () => {
  const fixtureRoot = path.join(__dirname, 'fixtures');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-golden-'));
  const maliciousFixture = Buffer.from(
    fs.readFileSync(path.join(fixtureRoot, 'malicious-tailwind.config.fixture.b64'), 'utf8').trim(),
    'base64',
  ).toString('utf8');
  fs.writeFileSync(path.join(root, 'malicious-tailwind.config.fixture'), maliciousFixture);

  const malicious = scan({ cwd: root, roots: ['malicious-tailwind.config.fixture'] });
  const clean = scan({ cwd: fixtureRoot, roots: ['clean-tailwind.config.fixture'] });

  assert.equal(malicious.ok, false);
  assert.equal(clean.ok, true);
});

test('formatResult supports json and sarif output', () => {
  const result = {
    findings: [
      { id: 'x', file: 'a.js', line: 2, detail: 'bad' },
    ],
  };

  assert.equal(JSON.parse(formatResult(result, 'json')).findings[0].id, 'x');
  assert.equal(JSON.parse(formatResult(result, 'sarif')).version, '2.1.0');
});
