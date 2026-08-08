import { useState } from 'react';
import {
  FileText, FolderOpen, ChevronRight, ChevronDown,
  AlertTriangle, CheckCircle2, RotateCcw, Shield
} from 'lucide-react';
import { getHighestSeverity, groupFindingsByFile } from '../engine/scanner.js';

/**
 * Build a tree structure from flat file paths.
 */
function buildTree(files, findingsByFile) {
  const root = { name: '', children: {}, files: [] };

  for (const file of files) {
    const parts = file.path.split('/');
    let current = root;

    for (let i = 0; i < parts.length - 1; i++) {
      if (!current.children[parts[i]]) {
        current.children[parts[i]] = { name: parts[i], children: {}, files: [] };
      }
      current = current.children[parts[i]];
    }

    current.files.push({
      ...file,
      findings: findingsByFile[file.path] || [],
    });
  }

  return root;
}

/**
 * Recursive tree node renderer
 */
function TreeNode({ name, node, depth, selectedFile, onSelectFile }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = Object.keys(node.children).length > 0 || node.files.length > 0;

  const countFindings = (n) => {
    let count = 0;
    for (const f of n.files) count += f.findings.length;
    for (const child of Object.values(n.children)) count += countFindings(child);
    return count;
  };

  const totalFindings = countFindings(node);

  if (name === '') {
    return (
      <>
        {Object.entries(node.children).map(([childName, childNode]) => (
          <TreeNode
            key={childName}
            name={childName}
            node={childNode}
            depth={0}
            selectedFile={selectedFile}
            onSelectFile={onSelectFile}
          />
        ))}
        {node.files.map((file) => (
          <FileNode
            key={file.path}
            file={file}
            depth={0}
            isSelected={selectedFile === file.path}
            onSelect={() => onSelectFile(file.path)}
          />
        ))}
      </>
    );
  }

  return (
    <>
      <div
        className="sidebar__item"
        style={{ paddingLeft: `${depth * 14 + 12}px`, cursor: 'pointer' }}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="sidebar__item-left">
          {hasChildren ? (
            expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />
          ) : (
            <span style={{ width: 14 }} />
          )}
          <FolderOpen size={15} style={{ color: 'var(--primary)' }} />
          <span style={{ fontSize: '0.84rem', fontWeight: 600 }}>{name}</span>
        </div>
        {totalFindings > 0 && (
          <span className="sidebar__item-badge" style={{ background: 'var(--severity-critical-bg)', color: 'var(--severity-critical)' }}>
            {totalFindings}
          </span>
        )}
      </div>

      {expanded && (
        <>
          {Object.entries(node.children).map(([childName, childNode]) => (
            <TreeNode
              key={childName}
              name={childName}
              node={childNode}
              depth={depth + 1}
              selectedFile={selectedFile}
              onSelectFile={onSelectFile}
            />
          ))}
          {node.files.map((file) => (
            <FileNode
              key={file.path}
              file={file}
              depth={depth + 1}
              isSelected={selectedFile === file.path}
              onSelect={() => onSelectFile(file.path)}
            />
          ))}
        </>
      )}
    </>
  );
}

/**
 * Individual file node in the tree
 */
function FileNode({ file, depth, isSelected, onSelect }) {
  const hasIssues = file.findings.length > 0;

  return (
    <div
      className={`sidebar__item ${isSelected ? 'sidebar__item--active' : ''}`}
      style={{ paddingLeft: `${depth * 14 + 12}px` }}
      onClick={onSelect}
    >
      <div className="sidebar__item-left">
        <FileText size={14} style={{ color: hasIssues ? 'var(--severity-high)' : 'var(--text-tertiary)' }} />
        <span style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)' }}>{file.name}</span>
      </div>
      {hasIssues ? (
        <span className="sidebar__item-badge" style={{ background: 'var(--severity-critical-bg)', color: 'var(--severity-critical)' }}>
          {file.findings.length}
        </span>
      ) : (
        <span className="sidebar__item-badge" style={{ background: 'var(--status-success-bg)', color: 'var(--status-success)' }}>
          <CheckCircle2 size={10} />
        </span>
      )}
    </div>
  );
}

/**
 * FileTree component
 */
export default function FileTree({ files, findings, selectedFile, onSelectFile, onReset }) {
  const findingsByFile = groupFindingsByFile(findings);
  const tree = buildTree(files, findingsByFile);

  return (
    <div style={{ background: 'var(--bg-surface)', padding: '20px', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-color)', boxShadow: 'var(--shadow-card)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={18} style={{ color: 'var(--primary)' }} />
          Pipeline Asset Posture
        </h3>
        <button className="btn btn--ghost btn--sm" onClick={onReset}>
          <RotateCcw size={13} />
          Reset
        </button>
      </div>

      {/* Show All filter option */}
      <div
        className={`sidebar__item ${selectedFile === null ? 'sidebar__item--active' : ''}`}
        style={{ marginBottom: '8px' }}
        onClick={() => onSelectFile(null)}
      >
        <div className="sidebar__item-left">
          <AlertTriangle size={15} style={{ color: 'var(--primary)' }} />
          <span style={{ fontWeight: 700 }}>All Pipeline Assets</span>
        </div>
        <span className="sidebar__item-badge" style={{ background: 'var(--primary)', color: 'white' }}>
          {findings.length}
        </span>
      </div>

      <div style={{ height: '1px', background: 'var(--border-color)', margin: '12px 0' }} />

      <TreeNode
        name=""
        node={tree}
        depth={0}
        selectedFile={selectedFile}
        onSelectFile={onSelectFile}
      />
    </div>
  );
}
