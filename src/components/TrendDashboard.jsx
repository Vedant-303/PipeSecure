import { useState, useMemo } from 'react';
import {
  ShieldAlert, ShieldCheck, Activity, RefreshCw,
  Trash2, ChevronRight, Layers, Lock, Bot, Zap,
  Download, FileText, CheckCircle2, AlertTriangle, ArrowUpRight, Database, Package, Key
} from 'lucide-react';
import {
  getScanHistory,
  calculatePostureScore,
  clearScanHistory,
  saveScanToHistory
} from '../engine/historyStore.js';

/**
 * TrendDashboard — Dynamic DevSecOps Pipeline Security Dashboard
 */
export default function TrendDashboard({ currentScanResult, onSimulateRemediation, onNavigateTab }) {
  const [history, setHistory] = useState(() => getScanHistory());

  const latestScan = currentScanResult || (history.length > 0 ? history[history.length - 1] : null);
  const summary = latestScan?.summary || {
    totalFiles: 0,
    scannedFiles: 0,
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    filesWithFindings: 0,
    cleanFiles: 0,
    engineMode: 'static',
  };

  const findings = latestScan?.findings || [];
  const posture = calculatePostureScore(summary);
  const isClean = posture.score >= 85;

  // Breakdown findings by category dynamically
  const categoryCounts = useMemo(() => {
    const counts = { secrets: 0, storage_access: 0, encryption: 0, dependencies: 0 };
    findings.forEach(f => {
      if (counts[f.category] !== undefined) counts[f.category]++;
    });
    return counts;
  }, [findings]);

  // Asset posture list (files ranked by vulnerability density)
  const assetPostureList = useMemo(() => {
    if (!latestScan || !latestScan.summary) return [];
    
    // Group findings by file
    const fileFindingsMap = {};
    findings.forEach(f => {
      if (!fileFindingsMap[f.filePath]) fileFindingsMap[f.filePath] = [];
      fileFindingsMap[f.filePath].push(f);
    });

    const assetItems = [];
    const scannedPaths = new Set(findings.map(f => f.filePath));

    // Files with findings
    for (const [filePath, fList] of Object.entries(fileFindingsMap)) {
      const critHigh = fList.filter(f => f.severity === 'critical' || f.severity === 'high').length;
      const total = fList.length;
      let healthScore = Math.max(10, 100 - (critHigh * 25 + (total - critHigh) * 10));
      assetItems.push({
        filePath,
        findingCount: total,
        critHighCount: critHigh,
        healthScore,
        statusLabel: critHigh > 0 ? `${critHigh} Critical/High Threat${critHigh !== 1 ? 's' : ''}` : `${total} Finding${total !== 1 ? 's' : ''}`,
      });
    }

    // Sort by health score ascending (most vulnerable first)
    assetItems.sort((a, b) => a.healthScore - b.healthScore);
    return assetItems.slice(0, 5);
  }, [latestScan, findings]);

  // Handle Export CSV
  const handleExportCSV = () => {
    if (!findings || findings.length === 0) return;
    const headers = ['ID', 'Rule', 'Severity', 'Category', 'File', 'Line', 'Title', 'Exposed Data', 'Remediation'];
    const rows = findings.map(f => [
      f.id,
      f.ruleId,
      f.severity,
      f.category,
      f.filePath,
      f.line,
      `"${(f.title || '').replace(/"/g, '""')}"`,
      `"${(f.exposed || '').replace(/"/g, '""')}"`,
      `"${(f.remediation || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `pipesecure_security_findings_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    setExportOpen(false);
  };

  // Handle Export JSON
  const handleExportJSON = () => {
    if (!latestScan) return;
    const blob = new Blob([JSON.stringify(latestScan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `pipesecure_scan_report_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setExportOpen(false);
  };

  const handleSimulate = () => {
    const cleanSummary = {
      totalFiles: 11,
      scannedFiles: 11,
      totalFindings: 1,
      critical: 0,
      high: 0,
      medium: 1,
      low: 0,
      info: 0,
      filesWithFindings: 1,
      cleanFiles: 10,
      engineMode: summary.engineMode,
    };
    const simulatedResult = {
      summary: cleanSummary,
      findings: [
        {
          id: 'sim-1',
          ruleId: 'CFG-007',
          category: 'storage_access',
          severity: 'medium',
          title: 'S3 bucket missing versioning or access logging',
          filePath: 'infra/main.tf',
          line: 12,
          evidence: 'resource "aws_s3_bucket" "pipeline_staging" {',
          exposed: 'S3 bucket is configured without versioning enabled.',
          whyItMatters: 'Without versioning, deleted pipeline objects cannot be restored.',
          remediation: 'Enable S3 bucket versioning in your Terraform config.',
          remediationCode: 'resource "aws_s3_bucket_versioning" "staging" {\n  bucket = aws_s3_bucket.pipeline_staging.id\n  versioning_configuration { status = "Enabled" }\n}',
        },
      ],
      scannedAt: new Date().toISOString(),
    };
    const updated = saveScanToHistory(simulatedResult);
    setHistory(updated);
    if (onSimulateRemediation) onSimulateRemediation(simulatedResult);
  };

  // Top 3 critical findings for live stream
  const topStreamFindings = findings.slice(0, 3);

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Action Header & Engine Badge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {summary.engineMode === 'ai' ? (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(139, 92, 246, 0.12)',
              color: '#8b5cf6',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              fontSize: '0.8125rem',
              fontWeight: 700,
            }}>
              <Bot size={15} />
              AI-Enhanced Deep Engine ({summary.aiProvider || 'Multi-Provider'})
            </span>
          ) : (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              borderRadius: 'var(--radius-full)',
              background: 'var(--primary-light)',
              color: 'var(--primary)',
              border: '1px solid var(--primary-border)',
              fontSize: '0.8125rem',
              fontWeight: 700,
            }}>
              <Zap size={15} />
              Fast Deterministic Engine (Sub-5ms, 100% Offline)
            </span>
          )}
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-tertiary)' }}>
            Scanned {summary.scannedFiles} asset{summary.scannedFiles !== 1 ? 's' : ''} across your pipeline
          </span>
        </div>
      </div>

      {/* Top Category KPI Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
        
        {/* Posture Score KPI */}
        <div className="dashboard-card" style={{ padding: '18px 20px', borderLeft: `4px solid ${posture.color}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Security Posture Score
            </span>
            <span style={{
              padding: '2px 8px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.75rem',
              fontWeight: 800,
              background: isClean ? 'var(--status-success-bg)' : 'var(--severity-critical-bg)',
              color: posture.color,
            }}>
              GRADE {posture.grade}
            </span>
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: posture.color, marginTop: '8px' }}>
            {posture.score}<span style={{ fontSize: '1.1rem', color: 'var(--text-tertiary)', fontWeight: 600 }}>/100</span>
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            {posture.riskLevel} • {summary.totalFindings} Threat{summary.totalFindings !== 1 ? 's' : ''} Detected
          </div>
        </div>

        {/* Secrets KPI */}
        <div
          className="dashboard-card"
          style={{ padding: '18px 20px', cursor: 'pointer', borderLeft: '4px solid #ef4444' }}
          onClick={() => onNavigateTab && onNavigateTab('secrets')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Hardcoded Secrets
            </span>
            <Key size={18} style={{ color: '#ef4444' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '8px' }}>
            {categoryCounts.secrets}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            API keys, DB passwords, JWT tokens
          </div>
        </div>

        {/* Storage & Access KPI */}
        <div
          className="dashboard-card"
          style={{ padding: '18px 20px', cursor: 'pointer', borderLeft: '4px solid #3b82f6' }}
          onClick={() => onNavigateTab && onNavigateTab('storage_access')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Storage & Access Risk
            </span>
            <Database size={18} style={{ color: '#3b82f6' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '8px' }}>
            {categoryCounts.storage_access}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            Public S3 buckets, IAM wildcards
          </div>
        </div>

        {/* Dependency CVEs KPI */}
        <div
          className="dashboard-card"
          style={{ padding: '18px 20px', cursor: 'pointer', borderLeft: '4px solid #8b5cf6' }}
          onClick={() => onNavigateTab && onNavigateTab('dependencies')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Dependency CVEs
            </span>
            <Package size={18} style={{ color: '#8b5cf6' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '8px' }}>
            {categoryCounts.dependencies}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            Vulnerable PyPI / npm advisory matches
          </div>
        </div>

      </div>

      {/* Main Security Forecast Grid */}
      <div className="dashboard-grid">
        
        {/* Critical Threat Alert Banner */}
        <div className={`alert-card ${isClean ? 'alert-card--clean' : ''}`}>
          <div className="alert-card__top">
            <div className="alert-card__badge" style={{ color: isClean ? 'var(--status-success)' : 'var(--severity-critical)' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: isClean ? 'var(--status-success)' : 'var(--severity-critical)', display: 'inline-block' }} />
              {isClean ? 'ALL PIPELINES SECURE' : 'ACTIVE PIPELINE RISKS DETECTED'}
            </div>
            <div className="alert-card__score-box">
              <span className="alert-card__score-label">RISK PENALTY</span>
              <div className="alert-card__score-val" style={{ color: isClean ? 'var(--status-success)' : 'var(--severity-critical)' }}>
                {100 - posture.score}<span style={{ fontSize: '1rem', color: 'var(--text-tertiary)' }}>/100</span>
              </div>
            </div>
          </div>

          <h2 className="alert-card__title">
            {isClean ? 'COMPLIANCE & POSTURE PASSED' : `${summary.critical + summary.high} HIGH-SEVERITY THREATS`}
          </h2>
          <p className="alert-card__desc">
            {isClean
              ? 'All data pipeline scripts, connection strings, S3 storage policies, and dependency manifests passed safety posture checks.'
              : 'Production credentials, wildcards, or vulnerable dependencies detected matching known data leak signature patterns.'}
          </p>

          <div className="alert-card__actions">
            <button className="btn btn--primary" onClick={() => onNavigateTab && onNavigateTab('secrets')}>
              <Lock size={15} />
              Review Findings ({summary.totalFindings})
            </button>
            <button className="btn btn--secondary" onClick={() => onNavigateTab && onNavigateTab('file_tree')}>
              <Layers size={15} />
              Inspect Assets ({summary.scannedFiles})
            </button>
          </div>
        </div>

        {/* Circular System Hardening Meter */}
        <div className="dashboard-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>System Hardening Index</h3>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)' }}>100% Client-Side</span>
          </div>

          <div className="gauge-container">
            <svg className="gauge-svg" viewBox="0 0 200 110">
              <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="var(--border-color)" strokeWidth="16" strokeDasharray="6 4" />
              <path
                d="M 20 100 A 80 80 0 0 1 180 100"
                fill="none"
                stroke={posture.color}
                strokeWidth="16"
                strokeDasharray="6 4"
                strokeDashoffset={160 * (1 - posture.score / 100)}
              />
            </svg>

            <div className="gauge-val">
              <div className="gauge-val__num">{posture.score}%</div>
              <div className="gauge-val__label">POSTURE INDEX</div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', fontWeight: 600 }}>
              <span style={{ color: 'var(--text-secondary)' }}>Clean Files Ratio</span>
              <span style={{ color: 'var(--primary)', fontWeight: 700 }}>
                {summary.scannedFiles > 0 ? Math.round((summary.cleanFiles / summary.scannedFiles) * 100) : 100}%
              </span>
            </div>
            <div style={{ height: '6px', background: 'var(--bg-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: `${summary.scannedFiles > 0 ? Math.round((summary.cleanFiles / summary.scannedFiles) * 100) : 100}%`, height: '100%', background: 'var(--primary)' }} />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', fontWeight: 600, marginTop: '4px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Secret Masking Integrity</span>
              <span style={{ color: 'var(--primary)', fontWeight: 700 }}>
                {categoryCounts.secrets === 0 ? '100%' : 'Action Required'}
              </span>
            </div>
            <div style={{ height: '6px', background: 'var(--bg-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: categoryCounts.secrets === 0 ? '100%' : '40%', height: '100%', background: categoryCounts.secrets === 0 ? 'var(--status-success)' : 'var(--severity-critical)' }} />
            </div>
          </div>
        </div>

      </div>

      {/* Bottom Grid: Live Incident Stream + Pipeline Asset Posture */}
      <div className="dashboard-grid">
        
        {/* Live Incident Stream */}
        <div className="dashboard-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={18} style={{ color: 'var(--severity-critical)' }} />
              Incident Stream Preview
            </h3>
            <button className="btn btn--ghost btn--sm" onClick={() => onNavigateTab && onNavigateTab('secrets')}>
              View All ({findings.length})
              <ChevronRight size={14} />
            </button>
          </div>

          <div className="findings-stream">
            {topStreamFindings.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--text-tertiary)' }}>
                <CheckCircle2 size={32} style={{ color: 'var(--status-success)', marginBottom: '8px' }} />
                <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>Zero Security Incidents</div>
                <div style={{ fontSize: '0.8rem' }}>No active vulnerabilities in scanned pipeline files</div>
              </div>
            ) : (
              topStreamFindings.map(finding => (
                <div
                  key={finding.id}
                  className={`stream-card stream-card--${finding.severity}`}
                  onClick={() => onNavigateTab && onNavigateTab(finding.category)}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="stream-card__top">
                    <div className="stream-card__title-group">
                      <div className="stream-card__icon">
                        <ShieldAlert size={16} />
                      </div>
                      <div>
                        <div className="stream-card__title">{finding.title}</div>
                        <div className="stream-card__meta">
                          <span>{finding.filePath}:{finding.line}</span>
                          <span className={`pill pill--${finding.category}`}>
                            {finding.category === 'secrets' && '🔑 Secrets'}
                            {finding.category === 'storage_access' && '🪣 Storage'}
                            {finding.category === 'encryption' && '🔒 Encryption'}
                            {finding.category === 'dependencies' && '📦 Dependencies'}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="stream-card__actions">
                      <button className="btn btn--secondary btn--sm">Inspect</button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Pipeline Asset Posture */}
        <div className="dashboard-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} style={{ color: 'var(--primary)' }} />
              Pipeline Assets Risk Density
            </h3>
            <button className="btn btn--ghost btn--sm" onClick={() => onNavigateTab && onNavigateTab('file_tree')}>
              Inspect All Assets ({summary.scannedFiles})
              <ChevronRight size={14} />
            </button>
          </div>

          <div className="asset-posture-list">
            {assetPostureList.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--text-tertiary)' }}>
                <CheckCircle2 size={32} style={{ color: 'var(--status-success)', marginBottom: '8px' }} />
                <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>All Assets Clean</div>
              </div>
            ) : (
              assetPostureList.map(asset => (
                <div
                  key={asset.filePath}
                  className="asset-posture-item"
                  onClick={() => onNavigateTab && onNavigateTab('file_tree')}
                  style={{ cursor: 'pointer' }}
                >
                  <div>
                    <div className="asset-posture-item__name">{asset.filePath}</div>
                    <span style={{ fontSize: '11px', color: asset.critHighCount > 0 ? 'var(--severity-critical)' : 'var(--text-secondary)' }}>
                      {asset.statusLabel}
                    </span>
                  </div>
                  <span className="asset-posture-item__score" style={{ color: asset.healthScore < 70 ? 'var(--severity-critical)' : 'var(--status-success)' }}>
                    {asset.healthScore}%
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

    </div>
  );
}
