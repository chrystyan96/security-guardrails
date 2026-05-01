'use strict';

function formatResult(result, format = 'text') {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }
  if (format === 'sarif') {
    return JSON.stringify(toSarif(result), null, 2);
  }
  return formatFindings(result.findings || []);
}

function formatFindings(findings) {
  if (findings.length === 0) {
    return '[security-guardrails] OK';
  }
  return [
    '[security-guardrails] Suspicious artifact(s) blocked:',
    ...findings.map((item) => `- ${item.id}: ${item.file}:${item.line || 1} - ${item.detail}`),
  ].join('\n');
}

function toSarif(result) {
  const findings = result.findings || [];
  const rules = new Map();
  for (const finding of findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        name: finding.id,
        shortDescription: { text: finding.id },
        fullDescription: { text: finding.detail || finding.id },
        defaultConfiguration: { level: 'error' },
      });
    }
  }
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'security-guardrails',
            informationUri: 'https://github.com/TwinSparkGames/security-guardrails',
            rules: Array.from(rules.values()),
          },
        },
        results: findings.map((finding) => ({
          ruleId: finding.id,
          level: 'error',
          message: { text: finding.detail },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: { startLine: finding.line || 1 },
              },
            },
          ],
        })),
      },
    ],
  };
}

module.exports = {
  formatFindings,
  formatResult,
  toSarif,
};
