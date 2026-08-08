import { useState, useCallback, useMemo } from 'react';
import Sidebar from './components/Sidebar.jsx';
import Header from './components/Header.jsx';
import FileUpload from './components/FileUpload.jsx';
import FileTree from './components/FileTree.jsx';
import FindingsList from './components/FindingsList.jsx';
import TrendDashboard from './components/TrendDashboard.jsx';
import { runScan } from './engine/scanner.js';
import { saveScanToHistory } from './engine/historyStore.js';
import demoFiles from './engine/demoData.js';

/**
 * App — Main Enterprise Security Dashboard Shell for PipeSecure
 */
export default function App() {
  const [appState, setAppState] = useState('upload'); // Initial state: 'upload' landing page
  const [activeNav, setActiveNav] = useState('upload'); // Initial nav: 'upload'
  const [files, setFiles] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  const isUploadScreen = appState === 'upload' && activeNav === 'upload';

  // Handle files loaded from upload zone or demo sample loader
  const handleFilesLoaded = useCallback(async (loadedFiles, aiConfigOverride) => {
    setFiles(loadedFiles);
    setAppState('scanning');
    setSelectedFile(null);

    try {
      const result = await runScan(loadedFiles, aiConfigOverride);
      setScanResult(result);
      saveScanToHistory(result);
      setAppState('results');
      setActiveNav('dashboard'); // Navigate to dashboard results after scanning
    } catch (err) {
      console.error('Scan error:', err);
      setAppState('results');
      setActiveNav('dashboard');
    }
  }, []);

  const handleLoadDemo = useCallback(() => {
    handleFilesLoaded(demoFiles);
  }, [handleFilesLoaded]);

  const handleReset = useCallback(() => {
    setAppState('upload');
    setActiveNav('upload');
    setFiles([]);
    setScanResult(null);
    setSelectedFile(null);
  }, []);

  // Compute category summary metrics for sidebar badges
  const summaryMetrics = useMemo(() => {
    if (!scanResult) return null;
    const counts = { secretsCount: 0, storageCount: 0, encryptionCount: 0, depCount: 0 };
    (scanResult.findings || []).forEach(f => {
      if (f.category === 'secrets') counts.secretsCount++;
      if (f.category === 'storage_access') counts.storageCount++;
      if (f.category === 'encryption') counts.encryptionCount++;
      if (f.category === 'dependencies') counts.depCount++;
    });
    return counts;
  }, [scanResult]);

  // Page title and subtitle mapping
  const getHeaderTitles = () => {
    switch (activeNav) {
      case 'dashboard':
        return { title: 'Dashboard', subtitle: 'Real-time client-side threat detection and pipeline security analysis' };
      case 'secrets':
        return { title: 'Threats & Hardcoded Secrets', subtitle: 'Detected API keys, database connection URIs, and private keys' };
      case 'storage_access':
        return { title: 'Storage & Access Misconfigurations', subtitle: 'Public S3 bucket policies, IAM wildcard permissions, and bucket ACLs' };
      case 'encryption':
        return { title: 'Encryption-at-Rest & SSL Compliance', subtitle: 'Unencrypted RDS/Redshift/EBS volumes and unencrypted database connections' };
      case 'dependencies':
        return { title: 'Package Dependency Vulnerabilities', subtitle: 'OSV API advisory matches across requirements.txt, pyproject.toml, package.json' };
      case 'file_tree':
        return { title: 'Pipeline Assets Posture', subtitle: 'Security health index mapped across all scanned pipeline files' };
      case 'upload':
        return { title: 'Scan New Pipeline', subtitle: 'Upload DAGs, dbt models, config YAMLs, or scripts for 100% client-side security scanning' };
      default:
        return { title: 'Dashboard', subtitle: 'Real-time threat detection system' };
    }
  };

  const headerInfo = getHeaderTitles();

  return (
    <div className="app-shell">
      {/* Render Sidebar ONLY when NOT on the upload landing screen */}
      {!isUploadScreen && (
        <Sidebar
          activeNav={activeNav}
          onSelectNav={(nav) => {
            setActiveNav(nav);
            if (nav === 'upload') setAppState('upload');
            else if (scanResult) setAppState('results');
          }}
          summary={summaryMetrics}
          fileCount={files.length}
          onReset={handleReset}
        />
      )}

      {/* Main Viewport */}
      <div className="app-viewport">
        {/* Top Header Bar */}
        <Header
          title={headerInfo.title}
          subtitle={headerInfo.subtitle}
          scanResult={scanResult}
          showBrand={isUploadScreen}
        />

        {/* Content Workspace */}
        <main className="app-content">
          {isUploadScreen ? (
            <div style={{ display: 'flex', justifyContent: 'center', minHeight: '100%', padding: '12px 0 32px' }}>
              <FileUpload onFilesLoaded={handleFilesLoaded} onLoadDemo={handleLoadDemo} />
            </div>
          ) : appState === 'scanning' ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '75vh', padding: '24px' }}>
              <div className="scanning-overlay">
                <div className="scanning-spinner" />
                <h3 className="scanning-text">
                  Scanning {files.length} Pipeline Asset{files.length !== 1 ? 's' : ''}…
                </h3>
                <p className="scanning-subtext">
                  Executing static pattern matchers, checking secret signatures, querying OSV CVE databases, and evaluating threat posture rules.
                </p>
                <div style={{ display: 'flex', gap: '8px', marginTop: '20px', flexWrap: 'wrap', justifyContent: 'center' }}>
                  <span style={{ fontSize: '0.75rem', padding: '4px 10px', borderRadius: 'var(--radius-full)', background: 'var(--primary-light)', color: 'var(--primary)', fontWeight: 600 }}>
                    ⚡ Fast Policy Rules
                  </span>
                  <span style={{ fontSize: '0.75rem', padding: '4px 10px', borderRadius: 'var(--radius-full)', background: 'var(--bg-subtle)', color: 'var(--text-secondary)', fontWeight: 600, border: '1px solid var(--border-color)' }}>
                    🔒 100% Client-Side Privacy
                  </span>
                </div>
              </div>
            </div>
          ) : activeNav === 'dashboard' ? (
            <TrendDashboard
              currentScanResult={scanResult}
              onSimulateRemediation={(simulatedResult) => setScanResult(simulatedResult)}
              onNavigateTab={(tab) => setActiveNav(tab)}
            />
          ) : activeNav === 'file_tree' ? (
            <FileTree
              files={files}
              findings={scanResult?.findings || []}
              selectedFile={selectedFile}
              onSelectFile={(file) => {
                setSelectedFile(file);
                setActiveNav('secrets');
              }}
              onReset={handleReset}
            />
          ) : (
            /* Category / Threat Views */
            scanResult && (
              <FindingsList
                findings={scanResult.findings}
                summary={scanResult.summary}
                selectedFile={selectedFile}
                activeCategoryFilter={activeNav === 'secrets' ? 'secrets' : activeNav === 'storage_access' ? 'storage_access' : activeNav === 'encryption' ? 'encryption' : activeNav === 'dependencies' ? 'dependencies' : 'all'}
              />
            )
          )}
        </main>
      </div>
    </div>
  );
}
