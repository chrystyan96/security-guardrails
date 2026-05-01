'use strict';

const fs = require('node:fs');
const path = require('node:path');

const configFileName = '.security-guardrails.json';

function loadConfig(cwd = process.cwd(), explicitPath) {
  const configPath = explicitPath ? path.resolve(cwd, explicitPath) : path.join(cwd, configFileName);
  if (!fs.existsSync(configPath)) {
    return { config: {}, configPath: null };
  }
  try {
    return {
      config: JSON.parse(fs.readFileSync(configPath, 'utf8')),
      configPath,
    };
  } catch (error) {
    throw new Error(`Could not parse ${configPath}: ${error.message}`);
  }
}

function createDefaultConfig(cwd = process.cwd()) {
  const configPath = path.join(cwd, configFileName);
  if (fs.existsSync(configPath)) {
    return { configPath, changed: false };
  }
  const config = {
    roots: ['backend-go', 'backend', 'frontend', 'desktop', 'packages', 'scripts', '.github', '.vscode'],
    ignoreDirs: [],
    skipFiles: [],
    allowExecutables: [],
    extraSignatures: [],
    extraRegexSignatures: [],
    auditAllPackageScripts: false,
  };
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  return { configPath, changed: true };
}

module.exports = {
  configFileName,
  createDefaultConfig,
  loadConfig,
};
