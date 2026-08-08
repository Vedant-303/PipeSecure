/**
 * PipeSecure — Executive Report Exporter (Phase 4)
 *
 * Generates formatted Markdown security reports and machine-readable JSON dumps.
 * Triggers browser file downloads.
 */

import { calculatePostureScore } from './historyStore.js';

/**
 * Generate Markdown executive security report
 */
export function generateMarkdownReport(scanResult) {
  const { summary, findings, scannedAt } = scanResult;
  const posture = calculatePostureScore(summary);
  const formattedDate = new Date(scannedAt).toLocaleString();

  let md = `# PipeSecure — Security Scan Report\n\n`;
  md += `**Scanned At**: ${formattedDate}  \n`;
  md += `**Overall Security Posture**: Grade ${posture.grade} (${posture.score}% — ${posture.riskLevel})  \n`;
  md += `**Privacy Guarantee**: 100% Client-Side Scan (No code left the browser)  \n\n`;

  md += `---\n\n## 📊 Executive Summary\n\n`;
  md += `| Metric | Count |\n`;
  md += `|---|---|\n`;
  md += `| Total Files Scanned | ${summary.scannedFiles} |\n`;
  md += `| Total Security Findings | ${summary.totalFindings} |\n`;
  md += `| 🔴 Critical Severities | ${summary.critical} |\n`;
  md += `| 🟠 High Severities | ${summary.high} |\n`;
  md += `| 🟡 Medium Severities | ${summary.medium} |\n`;
  md += `| 🔵 Low Severities | ${summary.low} |\n`;
  md += `| ✅ Clean Files | ${summary.cleanFiles} |\n\n`;

  md += `---\n\n## 🛡️ Findings by Category\n\n`;
  const categories = { secrets: 0, storage_access: 0, encryption: 0, dependencies: 0 };
  findings.forEach(f => {
    if (categories[f.category] !== undefined) categories[f.category]++;
  });

  md += `- 🔑 **Secrets**: ${categories.secrets} finding(s)\n`;
  md += `- 🪣 **Storage & Access**: ${categories.storage_access} finding(s)\n`;
  md += `- 🔒 **Encryption**: ${categories.encryption} finding(s)\n`;
  md += `- 📦 **Dependencies**: ${categories.dependencies} finding(s)\n\n`;

  md += `---\n\n## 📋 Detailed Findings & Remediation\n\n`;

  if (findings.length === 0) {
    md += `*No security findings detected! Your pipeline files are clean.*\n\n`;
  } else {
    findings.forEach((f, idx) => {
      md += `### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
      md += `- **Rule ID**: \`${f.ruleId}\`\n`;
      md += `- **Location**: \`${f.filePath}:${f.line}\`\n`;
      md += `- **Category**: ${f.category}\n\n`;
      md += `**Evidence**:\n\`\`\`text\n${f.evidence}\n\`\`\`\n\n`;
      md += `**What's Exposed**: ${f.exposed}\n\n`;
      md += `**Why It Matters**: ${f.whyItMatters}\n\n`;
      md += `**How to Fix It**: ${f.remediation}\n\n`;
      if (f.remediationCode) {
        md += `\`\`\`bash\n${f.remediationCode}\n\`\`\`\n\n`;
      }
      md += `---\n\n`;
    });
  }

  md += `*Report generated automatically by PipeSecure.*  \n`;
  return md;
}

/**
 * Trigger browser file download
 */
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Export Markdown report
 */
export function exportMarkdownReport(scanResult) {
  const md = generateMarkdownReport(scanResult);
  const dateStr = new Date().toISOString().slice(0, 10);
  downloadFile(md, `PipeSecure_Report_${dateStr}.md`, 'text/markdown;charset=utf-8');
}

/**
 * Export JSON report
 */
export function exportJsonReport(scanResult) {
  const jsonStr = JSON.stringify(scanResult, null, 2);
  const dateStr = new Date().toISOString().slice(0, 10);
  downloadFile(jsonStr, `PipeSecure_Findings_${dateStr}.json`, 'application/json;charset=utf-8');
}
