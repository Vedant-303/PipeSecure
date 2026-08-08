/**
 * PipeSecure — Scan History & Posture Score Store (Phase 4)
 *
 * Persists scan history to localStorage (`pipesecure_scan_history`)
 * to track security posture trends over multiple scans.
 *
 * Calculates:
 * - Security Posture Score (0-100%) and Grade (A, B, C, F)
 * - Scan-over-scan deltas (findings added/fixed)
 */

const STORAGE_KEY = 'pipesecure_scan_history';

/**
 * Calculate Security Posture Score (0-100) and Letter Grade from summary
 * Formula weights findings by severity density per file.
 */
export function calculatePostureScore(summary) {
  if (!summary || summary.scannedFiles === 0) {
    return { score: 100, grade: 'A', riskLevel: 'Low Risk', color: 'var(--status-success)' };
  }

  // Weight penalty points per finding
  const penalty =
    summary.critical * 25 +
    summary.high * 10 +
    summary.medium * 3 +
    summary.low * 1;

  // Max score 100, minimum 0
  const score = Math.max(0, Math.min(100, Math.round(100 - (penalty / summary.scannedFiles) * 8)));

  let grade = 'F';
  let riskLevel = 'Critical Risk';
  let color = 'var(--severity-critical)';

  if (score >= 90) {
    grade = 'A';
    riskLevel = 'Low Risk';
    color = 'var(--status-success)';
  } else if (score >= 75) {
    grade = 'B';
    riskLevel = 'Moderate Risk';
    color = 'var(--severity-low)';
  } else if (score >= 50) {
    grade = 'C';
    riskLevel = 'Elevated Risk';
    color = 'var(--severity-medium)';
  } else {
    grade = 'F';
    riskLevel = 'High Security Risk';
    color = 'var(--severity-critical)';
  }

  return { score, grade, riskLevel, color };
}

/**
 * Get all stored scan history items
 */
export function getScanHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.warn('Failed to parse scan history from localStorage:', err);
    return [];
  }
}

/**
 * Save a new scan result to scan history
 */
export function saveScanToHistory(scanResult) {
  if (!scanResult || !scanResult.summary) return getScanHistory();

  const history = getScanHistory();
  const posture = calculatePostureScore(scanResult.summary);

  // Compute delta compared to previous scan
  const previousScan = history.length > 0 ? history[history.length - 1] : null;
  let deltaText = 'First scan';

  if (previousScan) {
    const diff = scanResult.summary.totalFindings - previousScan.summary.totalFindings;
    if (diff < 0) {
      deltaText = `Fixed ${Math.abs(diff)} finding${Math.abs(diff) !== 1 ? 's' : ''}`;
    } else if (diff > 0) {
      deltaText = `+${diff} new finding${diff !== 1 ? 's' : ''}`;
    } else {
      deltaText = 'Unchanged';
    }
  }

  // Count findings by category
  const categories = { secrets: 0, storage_access: 0, encryption: 0, dependencies: 0 };
  (scanResult.findings || []).forEach(f => {
    if (categories[f.category] !== undefined) categories[f.category]++;
  });

  const record = {
    id: `scan-${Date.now().toString(36)}`,
    scannedAt: new Date().toISOString(),
    summary: { ...scanResult.summary },
    posture,
    categories,
    deltaText,
  };

  const updatedHistory = [...history, record];
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedHistory));
  } catch (err) {
    console.warn('Failed to save scan history:', err);
  }

  return updatedHistory;
}

/**
 * Clear stored scan history
 */
export function clearScanHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.warn('Failed to clear scan history:', err);
  }
  return [];
}
