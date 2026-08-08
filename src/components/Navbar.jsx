import { useState } from 'react';
import {
  ShieldCheck, Lock, Download, FileText, FileCode,
  TrendingUp, Search, ChevronDown
} from 'lucide-react';
import { exportMarkdownReport, exportJsonReport } from '../engine/reportExporter.js';

export default function Navbar({ activeTab, onTabChange, scanResult }) {
  const [exportOpen, setExportOpen] = useState(false);

  return (
    <nav className="navbar" role="banner">
      <div className="navbar__brand">
        <div className="navbar__logo" aria-hidden="true">
          <ShieldCheck size={20} />
        </div>
        <h1 className="navbar__title">PipeSecure</h1>
        <span className="navbar__badge">Secrets · Config · Encryption · Vulnerabilities</span>
      </div>

      {/* Center Nav Tabs */}
      <div className="navbar__tabs">
        <button
          className={`nav-tab ${activeTab === 'scanner' ? 'nav-tab--active' : ''}`}
          onClick={() => onTabChange('scanner')}
        >
          <Search size={15} />
          Scanner & Findings
        </button>
        <button
          className={`nav-tab ${activeTab === 'trends' ? 'nav-tab--active' : ''}`}
          onClick={() => onTabChange('trends')}
        >
          <TrendingUp size={15} />
          Posture & Trends
        </button>
      </div>

      <div className="navbar__right">
        {/* Export Report Menu */}
        {scanResult && (
          <div style={{ position: 'relative' }}>
            <button
              className="btn btn--secondary btn--sm"
              onClick={() => setExportOpen(!exportOpen)}
            >
              <Download size={14} />
              Export Report
              <ChevronDown size={12} />
            </button>

            {exportOpen && (
              <div className="export-menu">
                <button
                  className="export-menu__item"
                  onClick={() => {
                    setExportOpen(false);
                    exportMarkdownReport(scanResult);
                  }}
                >
                  <FileText size={14} />
                  Export Markdown (.md)
                </button>
                <button
                  className="export-menu__item"
                  onClick={() => {
                    setExportOpen(false);
                    exportJsonReport(scanResult);
                  }}
                >
                  <FileCode size={14} />
                  Export JSON (.json)
                </button>
              </div>
            )}
          </div>
        )}

        <div className="navbar__privacy" title="All scanning happens in your browser. No data is uploaded to any server.">
          <Lock />
          <span>100% Client-Side Scan</span>
        </div>
      </div>
    </nav>
  );
}
