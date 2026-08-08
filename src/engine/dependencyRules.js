/**
 * PipeSecure — Dependency Rule Formatter (Phase 3)
 *
 * Converts OSV vulnerability records into standard PipeSecure Finding objects
 * with plain-language explanations and concrete remediation code.
 */

import { generateFindingId, Category } from './types.js';

/**
 * Format a list of vulnerability objects from osvClient into PipeSecure Finding objects.
 * @param {Array} osvVulns List of vulnerability objects from OSV API or fallback cache
 * @returns {Array<Finding>} List of formatted PipeSecure findings
 */
export function formatDependencyFindings(osvVulns) {
  if (!osvVulns || osvVulns.length === 0) return [];

  return osvVulns.map(v => {
    const dep = v.dependency;
    const upgradeVersion = v.fixedVersion ? `>=${v.fixedVersion}` : '';
    const installCmd = dep.ecosystem === 'npm'
      ? `npm install ${dep.name}@${v.fixedVersion || 'latest'}`
      : `pip install --upgrade "${dep.name}${upgradeVersion}"`;

    return {
      id: generateFindingId(),
      ruleId: `DEP-${v.id}`,
      category: Category.DEPENDENCIES,
      severity: v.severity,
      title: `Vulnerable dependency: ${dep.name} ${dep.version} (${v.id})`,
      filePath: dep.filePath,
      line: dep.line,
      evidence: `${dep.rawSpec}   ← ${v.id}: ${v.summary}`,
      rawMatch: dep.rawSpec,
      exposed: `Your pipeline relies on ${dep.name} version ${dep.version}, which contains a known security vulnerability (${v.id}).`,
      whyItMatters: `${v.details} Pinned vulnerable dependencies in pipeline manifests expose worker nodes to potential exploits during data ingestion and processing tasks.`,
      remediation: `Upgrade ${dep.name} to version ${v.fixedVersion || 'a patched release'} or newer to resolve this vulnerability.`,
      remediationCode: `# Upgrade command:\n${installCmd}\n\n# Or update ${dep.filePath.split('/').pop()} to:\n${dep.name}${upgradeVersion || '>=[patched_version]'}`,
    };
  });
}
