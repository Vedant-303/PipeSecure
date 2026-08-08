/**
 * PipeSecure — Core data types and severity constants.
 * All scan findings, rules, and file representations use these structures.
 */

/** Severity levels ordered by impact */
export const Severity = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
});

/** Numeric weight for sorting/aggregation */
export const SeverityWeight = Object.freeze({
  [Severity.CRITICAL]: 4,
  [Severity.HIGH]: 3,
  [Severity.MEDIUM]: 2,
  [Severity.LOW]: 1,
  [Severity.INFO]: 0,
});

/** Finding categories — groups rules by what they detect */
export const Category = Object.freeze({
  SECRETS: 'secrets',
  STORAGE_ACCESS: 'storage_access',
  ENCRYPTION: 'encryption',
  DEPENDENCIES: 'dependencies',
});

/** Human-readable category labels and icons */
export const CategoryMeta = Object.freeze({
  [Category.SECRETS]: { label: 'Secrets', icon: '🔑' },
  [Category.STORAGE_ACCESS]: { label: 'Storage & Access', icon: '🪣' },
  [Category.ENCRYPTION]: { label: 'Encryption', icon: '🔒' },
  [Category.DEPENDENCIES]: { label: 'Dependencies', icon: '📦' },
});

/**
 * @typedef {Object} ScanFile
 * @property {string} path      - Relative path from upload root (e.g. "dags/etl.py")
 * @property {string} name      - File name
 * @property {string} content   - Raw text content
 * @property {string} extension - File extension (e.g. ".py")
 */

/**
 * @typedef {Object} Finding
 * @property {string}   id           - Unique finding ID (uuid-like)
 * @property {string}   ruleId       - Rule identifier (e.g. "SEC-DB-CONN-STRING")
 * @property {string}   severity     - One of Severity values
 * @property {string}   title        - Short finding title
 * @property {string}   filePath     - Relative file path
 * @property {number}   line         - 1-based line number
 * @property {string}   evidence     - The matched line with secrets masked
 * @property {string}   rawMatch     - The raw regex match (used internally, never shown to user)
 * @property {string}   exposed      - Plain-language "what's exposed"
 * @property {string}   whyItMatters - Plain-language "why this matters"
 * @property {string}   remediation  - Step-by-step fix explanation
 * @property {string}   remediationCode - Copyable code snippet showing the fix
 */

/**
 * @typedef {Object} Rule
 * @property {string}   id           - Rule identifier
 * @property {string}   severity     - Default severity
 * @property {string}   title        - Human-readable rule name
 * @property {RegExp}   pattern      - Detection regex (with global flag)
 * @property {string[]} fileTypes    - Applicable file extensions (e.g. [".py", ".yaml"])
 * @property {Function} [validate]   - Optional post-match validator to reduce false positives
 * @property {Function} exposed      - Returns "what's exposed" string given match context
 * @property {string}   whyItMatters - Static explanation
 * @property {string}   remediation  - Static remediation text
 * @property {Function} remediationCode - Returns copyable fix code given match context
 */

/**
 * Generate a short unique ID for findings
 */
let _idCounter = 0;
export function generateFindingId() {
  _idCounter += 1;
  return `f-${Date.now().toString(36)}-${_idCounter.toString(36)}`;
}

/** Supported file extensions for scanning */
export const SCANNABLE_EXTENSIONS = new Set([
  '.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf',
  '.sql', '.env', '.sh', '.bash', '.tf', '.hcl',
  '.txt', '.properties', '.xml',
]);

/**
 * Check if a filename is scannable
 */
export function isScannable(filename) {
  const lower = filename.toLowerCase();
  // Always scan known manifest filenames
  const knownNames = [
    'requirements.txt', 'pipfile', 'pipfile.lock', 'setup.cfg',
    'pyproject.toml', 'package.json', 'package-lock.json',
    'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.env', '.env.local', '.env.production', '.env.development',
  ];
  if (knownNames.some(n => lower.endsWith(n))) return true;

  const ext = '.' + lower.split('.').pop();
  return SCANNABLE_EXTENSIONS.has(ext);
}
