import { useState, useMemo } from 'react';
import {
  Search, ChevronDown, ShieldAlert, ShieldX, AlertTriangle, Info,
  FileCode, Eye, MessageCircleWarning, Wrench, Copy, Check, Lock, ChevronUp, Bot
} from 'lucide-react';
import { CategoryMeta } from '../engine/types.js';

/**
 * Severity icon component
 */
function SeverityIcon({ severity, size = 16 }) {
  switch (severity) {
    case 'critical': return <ShieldX size={size} />;
    case 'high': return <ShieldAlert size={size} />;
    case 'medium': return <AlertTriangle size={size} />;
    case 'low': return <Info size={size} />;
    default: return <Info size={size} />;
  }
}

/**
 * Single Incident Card matching reference design
 */
function IncidentCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const categoryInfo = CategoryMeta[finding.category] || { label: finding.category, icon: '📋' };

  const handleCopy = async (e, text) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div
      className={`stream-card stream-card--${finding.severity}`}
      onClick={() => setExpanded(!expanded)}
      role="button"
      tabIndex={0}
      id={`finding-${finding.id}`}
    >
      <div className="stream-card__top">
        <div className="stream-card__title-group">
          <div className="stream-card__icon">
            <SeverityIcon severity={finding.severity} size={16} />
          </div>
          <div>
            <div className="stream-card__title">{finding.title}</div>
            <div className="stream-card__meta">
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                {finding.filePath}:{finding.line}
              </span>
              <span className={`pill pill--${finding.category}`}>
                {categoryInfo.icon} {categoryInfo.label}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', fontSize: '11px' }}>
                {finding.ruleId}
              </span>
            </div>
          </div>
        </div>

        <div className="stream-card__actions" onClick={(e) => e.stopPropagation()}>
          <button
            className="btn btn--secondary btn--sm"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {expanded ? 'Collapse' : 'Investigate'}
          </button>
        </div>
      </div>

      {/* Code Evidence snippet */}
      <div className="code-evidence">
        <span style={{ color: 'var(--text-tertiary)', userSelect: 'none' }}>
          LINE {String(finding.line).padStart(3, '0')} │{' '}
        </span>
        {finding.evidence}
      </div>

      {/* Expanded Guidance Drawer */}
      {expanded && (
        <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--border-color)' }}>
          {/* What's Exposed */}
          <div style={{ marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--severity-critical)', marginBottom: '4px' }}>
              <Eye size={14} />
              What's Exposed
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{finding.exposed}</p>
          </div>

          {/* Why It Matters */}
          <div style={{ marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '4px' }}>
              <MessageCircleWarning size={14} />
              Why It Matters
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{finding.whyItMatters}</p>
          </div>

          {/* AI Deep Analysis (if available) */}
          {finding.aiImpact && (
            <div style={{ marginBottom: '14px', background: 'var(--primary-light)', padding: '12px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--primary-border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '4px' }}>
                <Bot size={14} />
                🤖 AI Deep Context Analysis ({finding.aiConfidence}% Confidence)
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', margin: 0 }}>{finding.aiImpact}</p>
            </div>
          )}

          {/* How to Fix It */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--status-success)', marginBottom: '4px' }}>
              <Wrench size={14} />
              How to Fix It
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>{finding.remediation}</p>

            {(finding.aiRemediatedCode || finding.remediationCode) && (
              <div className="code-remediation">
                <button
                  className="btn btn--secondary btn--sm"
                  style={{ position: 'absolute', top: '8px', right: '8px' }}
                  onClick={(e) => handleCopy(e, finding.aiRemediatedCode || finding.remediationCode)}
                >
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                  {copied ? 'Copied' : 'Copy Remediation'}
                </button>
                <pre style={{ margin: 0 }}>{finding.aiRemediatedCode || finding.remediationCode}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * FindingsList Component — Reference-matched incident stream
 */
export default function FindingsList({ findings, summary, selectedFile, activeCategoryFilter }) {
  const [activeFilter, setActiveFilter] = useState('all');
  const [activeCategory, setActiveCategory] = useState(activeCategoryFilter || 'all');

  // Keep activeCategory in sync if prop changes
  useMemo(() => {
    if (activeCategoryFilter) setActiveCategory(activeCategoryFilter);
  }, [activeCategoryFilter]);

  const categoryCounts = useMemo(() => {
    const base = selectedFile ? findings.filter(f => f.filePath === selectedFile) : findings;
    return {
      all: base.length,
      secrets: base.filter(f => f.category === 'secrets').length,
      storage_access: base.filter(f => f.category === 'storage_access').length,
      encryption: base.filter(f => f.category === 'encryption').length,
      dependencies: base.filter(f => f.category === 'dependencies').length,
    };
  }, [findings, selectedFile]);

  const filteredFindings = useMemo(() => {
    let result = findings;

    if (selectedFile) {
      result = result.filter(f => f.filePath === selectedFile);
    }
    if (activeFilter !== 'all') {
      result = result.filter(f => f.severity === activeFilter);
    }
    if (activeCategory !== 'all') {
      result = result.filter(f => f.category === activeCategory);
    }

    return result;
  }, [findings, selectedFile, activeFilter, activeCategory]);

  return (
    <div style={{ maxWidth: '1000px' }}>
      {/* Category & Severity Filter Pills */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button
            className={`btn btn--sm ${activeCategory === 'all' ? 'btn--primary' : 'btn--secondary'}`}
            onClick={() => setActiveCategory('all')}
          >
            All Categories ({categoryCounts.all})
          </button>
          <button
            className={`btn btn--sm ${activeCategory === 'secrets' ? 'btn--primary' : 'btn--secondary'}`}
            onClick={() => setActiveCategory('secrets')}
          >
            🔑 Secrets ({categoryCounts.secrets})
          </button>
          <button
            className={`btn btn--sm ${activeCategory === 'storage_access' ? 'btn--primary' : 'btn--secondary'}`}
            onClick={() => setActiveCategory('storage_access')}
          >
            🪣 Storage ({categoryCounts.storage_access})
          </button>
          <button
            className={`btn btn--sm ${activeCategory === 'encryption' ? 'btn--primary' : 'btn--secondary'}`}
            onClick={() => setActiveCategory('encryption')}
          >
            🔒 Encryption ({categoryCounts.encryption})
          </button>
          <button
            className={`btn btn--sm ${activeCategory === 'dependencies' ? 'btn--primary' : 'btn--secondary'}`}
            onClick={() => setActiveCategory('dependencies')}
          >
            📦 Dependencies ({categoryCounts.dependencies})
          </button>
        </div>

        <div style={{ display: 'flex', gap: '6px' }}>
          {['all', 'critical', 'high', 'medium'].map((sev) => (
            <button
              key={sev}
              className={`btn btn--ghost btn--sm ${activeFilter === sev ? 'btn--secondary' : ''}`}
              style={{ textTransform: 'capitalize' }}
              onClick={() => setActiveFilter(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Incident Stream */}
      {filteredFindings.length === 0 ? (
        <div className="dashboard-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <ShieldAlert size={32} style={{ color: 'var(--text-tertiary)', marginBottom: '12px' }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>No Security Threats Found</h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>No security findings match your current filters.</p>
        </div>
      ) : (
        <div className="findings-stream">
          {filteredFindings.map((finding) => (
            <IncidentCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}
