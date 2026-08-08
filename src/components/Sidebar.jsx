import {
  ShieldCheck, LayoutDashboard, Key, Database, Lock,
  Package, FolderTree, Upload, Terminal, Settings
} from 'lucide-react';

/**
 * Sidebar Component — Persistent left navigation matching the Sentry dashboard reference
 */
export default function Sidebar({ activeNav, onSelectNav, summary, fileCount, onReset }) {
  const secretsCount = summary ? summary.secretsCount : 0;
  const storageCount = summary ? summary.storageCount : 0;
  const encryptionCount = summary ? summary.encryptionCount : 0;
  const depCount = summary ? summary.depCount : 0;
  const currentFileCount = fileCount || 0;

  return (
    <aside className="app-sidebar">
      <div>
        {/* Brand Header */}
        <div className="sidebar__brand">
          <div className="sidebar__logo">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="sidebar__brand-name">PipeSecure</h1>
            <div className="header__privacy" style={{ fontSize: '10px', padding: '2px 7px', marginTop: '2px' }} title="Scanning executes entirely in your browser. Zero code leaves your computer.">
              <Lock size={11} />
              <span>100% Client-Side</span>
            </div>
          </div>
        </div>

        {/* Main Menu */}
        <div className="sidebar__menu-label">Main Menu</div>
        <nav className="sidebar__nav">
          <button
            className={`sidebar__item ${activeNav === 'dashboard' ? 'sidebar__item--active' : ''}`}
            onClick={() => onSelectNav('dashboard')}
          >
            <div className="sidebar__item-left">
              <LayoutDashboard />
              <span>Dashboard</span>
            </div>
          </button>

          <button
            className={`sidebar__item ${activeNav === 'secrets' ? 'sidebar__item--active' : ''}`}
            onClick={() => onSelectNav('secrets')}
          >
            <div className="sidebar__item-left">
              <Key />
              <span>Threats & Secrets</span>
            </div>
            {secretsCount > 0 && <span className="sidebar__item-badge">{secretsCount}</span>}
          </button>

          <button
            className={`sidebar__item ${activeNav === 'storage_access' ? 'sidebar__item--active' : ''}`}
            onClick={() => onSelectNav('storage_access')}
          >
            <div className="sidebar__item-left">
              <Database />
              <span>Storage & Access</span>
            </div>
            {storageCount > 0 && <span className="sidebar__item-badge">{storageCount}</span>}
          </button>

          <button
            className={`sidebar__item ${activeNav === 'encryption' ? 'sidebar__item--active' : ''}`}
            onClick={() => onSelectNav('encryption')}
          >
            <div className="sidebar__item-left">
              <Lock />
              <span>Encryption</span>
            </div>
            {encryptionCount > 0 && <span className="sidebar__item-badge">{encryptionCount}</span>}
          </button>

          <button
            className={`sidebar__item ${activeNav === 'dependencies' ? 'sidebar__item--active' : ''}`}
            onClick={() => onSelectNav('dependencies')}
          >
            <div className="sidebar__item-left">
              <Package />
              <span>Dependencies</span>
            </div>
            {depCount > 0 && <span className="sidebar__item-badge">{depCount}</span>}
          </button>

          <button
            className={`sidebar__item ${activeNav === 'file_tree' ? 'sidebar__item--active' : ''}`}
            onClick={() => onSelectNav('file_tree')}
          >
            <div className="sidebar__item-left">
              <FolderTree />
              <span>Pipeline Assets</span>
            </div>
            {currentFileCount > 0 && <span className="sidebar__item-badge">{currentFileCount}</span>}
          </button>
        </nav>
      </div>

      {/* Footer Controls */}
      <div className="sidebar__footer">
        <button className="btn btn--secondary btn--sm" style={{ width: '100%', justifyContent: 'center' }} onClick={onReset}>
          <Upload size={14} />
          Scan New Pipeline
        </button>
      </div>
    </aside>
  );
}
