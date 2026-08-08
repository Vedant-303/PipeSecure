/**
 * PipeSecure — File Scanner Engine
 *
 * Iterates over uploaded files, applies matching secret detection rules,
 * extracts line numbers, masks sensitive content in evidence, and produces
 * structured Finding objects.
 *
 * Design: Entirely client-side — no data ever leaves the browser.
 */

import secretRules from './secretRules.js';
import configRules from './configRules.js';
import { extractDependencies } from './dependencyParser.js';
import { queryOSVBatch } from './osvClient.js';
import { formatDependencyFindings } from './dependencyRules.js';
import { generateFindingId, SeverityWeight, isScannable } from './types.js';

/** All rules merged from all phases */
const allRules = [...secretRules, ...configRules];

/**
 * Mask sensitive portions of a matched string for safe display.
 * Shows first 4 and last 2 chars; masks the rest with asterisks.
 * For short strings (< 10 chars), mask everything after first 2.
 */
function maskSecret(str) {
  if (!str || str.length < 4) return '****';
  if (str.length < 10) {
    return str.substring(0, 2) + '*'.repeat(str.length - 2);
  }
  return str.substring(0, 4) + '*'.repeat(Math.min(str.length - 6, 20)) + str.substring(str.length - 2);
}

/**
 * Mask secrets within a line of evidence for display purposes.
 * Replaces the matched secret portions while keeping the surrounding context.
 */
function maskLineEvidence(line, matchStr) {
  // For connection strings, mask the password portion
  const connMatch = matchStr.match(/:\/\/([^:]+):([^@]+)@/);
  if (connMatch) {
    const masked = matchStr.replace(connMatch[2], maskSecret(connMatch[2]));
    return line.replace(matchStr, masked);
  }

  // For key=value patterns, mask the value
  const kvMatch = matchStr.match(/[=:]\s*['"]?([a-zA-Z0-9_\-./+=]{8,})['"]?/);
  if (kvMatch) {
    const masked = matchStr.replace(kvMatch[1], maskSecret(kvMatch[1]));
    return line.replace(matchStr, masked);
  }

  // For JWT tokens, mask middle and end
  if (matchStr.startsWith('eyJ')) {
    return line.replace(matchStr, matchStr.substring(0, 12) + '…[MASKED]');
  }

  // Fallback: mask the middle of the match
  return line.replace(matchStr, maskSecret(matchStr));
}

/**
 * Get the file extension from a path
 */
function getExtension(filePath) {
  const parts = filePath.split('.');
  if (parts.length < 2) return '';
  return '.' + parts[parts.length - 1].toLowerCase();
}

/**
 * Find the 1-based line number and extract the line for a match index.
 */
function getLineInfo(content, matchIndex) {
  const beforeMatch = content.substring(0, matchIndex);
  const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;
  const lines = content.split('\n');
  const lineContent = lines[lineNumber - 1] || '';
  return { lineNumber, lineContent: lineContent.trimEnd() };
}

/**
 * Run all secret detection rules against a single file.
 * @param {ScanFile} file - File to scan
 * @returns {Finding[]} - Array of findings for this file
 */
function scanFile(file) {
  const findings = [];
  const ext = getExtension(file.path);

  for (const rule of allRules) {
    // Skip rules that don't apply to this file type
    if (rule.fileTypes && !rule.fileTypes.includes(ext)) {
      // Also check filename-based matches (.env files, etc.)
      const filename = file.name.toLowerCase();
      if (!filename.startsWith('.env')) continue;
    }

    // Reset regex state for global patterns
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;

    while ((match = pattern.exec(file.content)) !== null) {
      const { lineNumber, lineContent } = getLineInfo(file.content, match.index);

      // Run validator to reduce false positives
      if (rule.validate && !rule.validate(lineContent, match)) {
        continue;
      }

      const maskedEvidence = maskLineEvidence(lineContent, match[0]);

      findings.push({
        id: generateFindingId(),
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        filePath: file.path,
        line: lineNumber,
        evidence: maskedEvidence,
        rawMatch: match[0], // Internal use only, never displayed
        exposed: typeof rule.exposed === 'function' ? rule.exposed(match) : rule.exposed,
        whyItMatters: rule.whyItMatters,
        remediation: rule.remediation,
        remediationCode: typeof rule.remediationCode === 'function'
          ? rule.remediationCode(match)
          : rule.remediationCode,
      });
    }
  }

  return findings;
}

import { enrichFindingsWithAI } from './universalAIClient.js';

/**
 * Run a complete scan across all uploaded files (static rules + OSV dependency vulnerabilities + optional AI enrichment).
 * @param {ScanFile[]} files - Array of files to scan
 * @param {Object} [aiConfig] - Optional AI engine configuration
 * @returns {Promise<{ findings: Finding[], summary: Object, scannedAt: string }>}
 */
export async function runScan(files, aiConfig) {
  let allFindings = [];
  const scannable = files.filter(f => isScannable(f.name));

  // 1. Static pattern scan (secrets & infra configs)
  for (const file of scannable) {
    const fileFindings = scanFile(file);
    allFindings.push(...fileFindings);
  }

  // 2. Dependency manifest scan (OSV vulnerability API query)
  const extractedDeps = [];
  for (const file of scannable) {
    const fileDeps = extractDependencies(file);
    if (fileDeps.length > 0) {
      extractedDeps.push(...fileDeps);
    }
  }

  if (extractedDeps.length > 0) {
    const osvVulns = await queryOSVBatch(extractedDeps);
    const depFindings = formatDependencyFindings(osvVulns);
    allFindings.push(...depFindings);
  }

  // 3. Optional Universal AI Analysis Enrichment
  if (aiConfig && aiConfig.engineMode === 'ai' && (aiConfig.apiKey || aiConfig.provider === 'custom')) {
    try {
      allFindings = await enrichFindingsWithAI(scannable, allFindings, aiConfig);
    } catch (err) {
      console.warn('AI enrichment failed, falling back to static findings:', err);
    }
  }

  // Sort by severity (critical first), then by file path
  allFindings.sort((a, b) => {
    const sevDiff = (SeverityWeight[b.severity] || 0) - (SeverityWeight[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return a.filePath.localeCompare(b.filePath);
  });

  // Build summary
  const summary = {
    totalFiles: files.length,
    scannedFiles: scannable.length,
    totalFindings: allFindings.length,
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
    filesWithFindings: new Set(allFindings.map(f => f.filePath)).size,
    cleanFiles: scannable.length - new Set(allFindings.map(f => f.filePath)).size,
    engineMode: aiConfig?.engineMode || 'static',
    aiProvider: aiConfig?.engineMode === 'ai' ? aiConfig.provider : null,
  };

  return {
    findings: allFindings,
    summary,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Get findings grouped by file path
 */
export function groupFindingsByFile(findings) {
  const grouped = {};
  for (const finding of findings) {
    if (!grouped[finding.filePath]) {
      grouped[finding.filePath] = [];
    }
    grouped[finding.filePath].push(finding);
  }
  return grouped;
}

/**
 * Get the highest severity among a list of findings
 */
export function getHighestSeverity(findings) {
  if (!findings || findings.length === 0) return null;
  return findings.reduce((highest, f) => {
    return (SeverityWeight[f.severity] || 0) > (SeverityWeight[highest] || 0)
      ? f.severity
      : highest;
  }, findings[0].severity);
}
