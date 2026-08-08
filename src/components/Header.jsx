import { useState, useEffect } from 'react';
import {
  Lock, Download, FileText, FileCode, ChevronDown, ShieldCheck, Sun, Moon
} from 'lucide-react';
import { exportMarkdownReport, exportJsonReport } from '../engine/reportExporter.js';

/**
 * Header Component — Global top bar
 */
export default function Header({ title, subtitle, scanResult, showBrand }) {
  const [exportOpen, setExportOpen] = useState(false);
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('pipesecure_theme');
    if (saved) return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('pipesecure_theme', theme);
  }, [theme]);

  return (
    <header className="app-header">
      <div className="header__left" style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        {showBrand ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="sidebar__logo" style={{ width: '40px', height: '40px' }}>
              <ShieldCheck size={24} />
            </div>
            <div>
              <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: '1.1' }}>
                PipeSecure
              </h1>
              <div className="header__privacy" style={{ fontSize: '10px', padding: '2px 8px', marginTop: '3px', width: 'fit-content' }} title="Scanning executes entirely in your browser. Zero code leaves your computer.">
                <Lock size={11} />
                <span>100% Client-Side</span>
              </div>
            </div>
          </div>
        ) : (
          <div>
            <h1 className="header__title">{title || 'Dashboard'}</h1>
            <p className="header__subtitle">{subtitle || 'Real-time pipeline security scanning and threat posture analysis'}</p>
          </div>
        )}
      </div>

      <div className="header__right" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {/* Theme Toggle Button */}
        <button
          className="btn btn--secondary btn--sm"
          onClick={() => setTheme(prev => (prev === 'dark' ? 'light' : 'dark'))}
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          {theme === 'dark' ? <Sun size={15} style={{ color: '#fbbf24' }} /> : <Moon size={15} style={{ color: '#6366f1' }} />}
          <span style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </button>


        {/* Export Report Action */}
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
              <div className="export-dropdown">
                <button
                  className="export-dropdown__item"
                  onClick={() => {
                    setExportOpen(false);
                    exportMarkdownReport(scanResult);
                  }}
                >
                  <FileText size={14} />
                  Export Markdown (.md)
                </button>
                <button
                  className="export-dropdown__item"
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
      </div>
    </header>
  );
}
