import { useCallback, useRef, useState, useEffect } from 'react';
import { Upload, FolderOpen, FileText, Lock, Zap, Bot, Key, CheckCircle, AlertCircle, RefreshCw } from 'lucide-react';
import { isScannable } from '../engine/types.js';
import { AI_PROVIDERS, testAIConnection, fetchAvailableModels } from '../engine/universalAIClient.js';
import { getAIConfig, saveAIConfig } from '../engine/aiConfigStore.js';

/**
 * FileUpload — Drag-and-Drop Landing Interface with Engine Selector
 */
export default function FileUpload({ onFilesLoaded }) {
  const [isDragActive, setIsDragActive] = useState(false);
  const [isParsingFolder, setIsParsingFolder] = useState(false);
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  // Engine configuration state
  const [aiConfig, setAiConfig] = useState(getAIConfig());
  const [availableModels, setAvailableModels] = useState([]);
  const [fetchingModels, setFetchingModels] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    saveAIConfig(aiConfig);
  }, [aiConfig]);

  // Fetch live model list whenever provider, apiKey, or baseUrl changes
  useEffect(() => {
    if (aiConfig.engineMode !== 'ai') return;
    let isMounted = true;
    setFetchingModels(true);

    fetchAvailableModels({
      provider: aiConfig.provider,
      apiKey: aiConfig.apiKey,
      baseUrl: aiConfig.baseUrl,
    }).then(models => {
      if (isMounted) {
        setAvailableModels(models);
        setFetchingModels(false);
        // If current selected model is not in fetched list, set to first model
        if (models.length > 0 && !models.includes(aiConfig.model)) {
          setAiConfig(prev => ({ ...prev, model: models[0] }));
        }
      }
    });

    return () => { isMounted = false; };
  }, [aiConfig.engineMode, aiConfig.provider, aiConfig.apiKey, aiConfig.baseUrl]);

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    const res = await testAIConnection(aiConfig);
    setTestingConnection(false);
    setTestResult(res);
  };

  /**
   * Recursively read all entries from a DataTransferItem (directory support)
   */
  const readEntries = useCallback(async (entry, basePath = '') => {
    const results = [];

    if (entry.isFile) {
      const file = await new Promise((resolve) => entry.file(resolve));
      const path = basePath ? `${basePath}/${file.name}` : file.name;
      if (isScannable(file.name)) {
        const content = await file.text();
        results.push({
          path,
          name: file.name,
          extension: '.' + file.name.split('.').pop().toLowerCase(),
          content,
        });
      }
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const entries = await new Promise((resolve) => {
        const allEntries = [];
        const readBatch = () => {
          reader.readEntries((batch) => {
            if (batch.length === 0) {
              resolve(allEntries);
            } else {
              allEntries.push(...batch);
              readBatch();
            }
          });
        };
        readBatch();
      });

      const dirPath = basePath ? `${basePath}/${entry.name}` : entry.name;
      for (const child of entries) {
        const childResults = await readEntries(child, dirPath);
        results.push(...childResults);
      }
    }

    return results;
  }, []);

  /**
   * Handle files from drag & drop
   */
  const handleDrop = useCallback(async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    setIsParsingFolder(true);

    try {
      const items = e.dataTransfer.items;
      if (!items || items.length === 0) {
        setIsParsingFolder(false);
        return;
      }

      const allFiles = [];

      for (let i = 0; i < items.length; i++) {
        const entry = items[i].webkitGetAsEntry?.();
        if (entry) {
          const files = await readEntries(entry);
          allFiles.push(...files);
        }
      }

      if (allFiles.length > 0) {
        onFilesLoaded(allFiles, aiConfig);
      } else {
        setIsParsingFolder(false);
      }
    } catch (err) {
      console.error('Drop error:', err);
      setIsParsingFolder(false);
    }
  }, [readEntries, onFilesLoaded, aiConfig]);

  /**
   * Handle files from input[type=file] (multi-file or folder)
   */
  const handleInputChange = useCallback(async (e) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setIsParsingFolder(true);

    try {
      const allFiles = [];

      for (const file of fileList) {
        if (!isScannable(file.name)) continue;

        const path = file.webkitRelativePath || file.name;
        const content = await file.text();

        allFiles.push({
          path,
          name: file.name,
          extension: '.' + file.name.split('.').pop().toLowerCase(),
          content,
        });
      }

      if (allFiles.length > 0) {
        onFilesLoaded(allFiles, aiConfig);
      } else {
        setIsParsingFolder(false);
      }
    } catch (err) {
      console.error('File input error:', err);
      setIsParsingFolder(false);
    }

    e.target.value = '';
  }, [onFilesLoaded, aiConfig]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }, []);

  const currentProviderDef = AI_PROVIDERS[aiConfig.provider] || AI_PROVIDERS.openai;

  if (isParsingFolder) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', padding: '24px', width: '100%', maxWidth: '780px', margin: '0 auto' }}>
        <div className="scanning-overlay">
          <div className="scanning-spinner" />
          <h3 className="scanning-text">Reading & Extracting Folder Assets…</h3>
          <p className="scanning-subtext">
            Traversing pipeline directory structure and extracting scannable DAGs, Terraform scripts, requirements, and config files.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ width: '100%', maxWidth: '780px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Engine Selection Bar */}
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-xl)', padding: '20px', boxShadow: 'var(--shadow-card)' }}>
        <h4 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '14px' }}>
          Select Security Scan Engine
        </h4>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          {/* Static Engine Pill */}
          <div
            onClick={() => setAiConfig(prev => ({ ...prev, engineMode: 'static' }))}
            style={{
              padding: '14px 16px',
              borderRadius: 'var(--radius-lg)',
              border: `2px solid ${aiConfig.engineMode === 'static' ? 'var(--primary)' : 'var(--border-color)'}`,
              background: aiConfig.engineMode === 'static' ? 'var(--primary-light)' : 'var(--bg-surface)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
              transition: 'all 150ms ease',
            }}
          >
            <Zap size={20} style={{ color: 'var(--primary)', flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Fast Deterministic Engine
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                100% Client-Side • Zero API key needed • Sub-5ms regex & policy rules
              </div>
            </div>
          </div>

          {/* AI Engine Pill */}
          <div
            onClick={() => setAiConfig(prev => ({ ...prev, engineMode: 'ai' }))}
            style={{
              padding: '14px 16px',
              borderRadius: 'var(--radius-lg)',
              border: `2px solid ${aiConfig.engineMode === 'ai' ? 'var(--primary)' : 'var(--border-color)'}`,
              background: aiConfig.engineMode === 'ai' ? 'var(--primary-light)' : 'var(--bg-surface)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
              transition: 'all 150ms ease',
            }}
          >
            <Bot size={20} style={{ color: '#8b5cf6', flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                AI-Enhanced Deep Analysis
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                OpenAI, Claude, Gemini, or Local LLM • Deep risk & refactored code fixes
              </div>
            </div>
          </div>
        </div>

        {/* AI Provider Config Form */}
        {aiConfig.engineMode === 'ai' && (
          <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  AI Provider
                </label>
                <select
                  className="input"
                  style={{ width: '100%', padding: '8px 12px', fontSize: '0.85rem' }}
                  value={aiConfig.provider}
                  onChange={(e) => {
                    const provKey = e.target.value;
                    const pDef = AI_PROVIDERS[provKey];
                    setAiConfig(prev => ({
                      ...prev,
                      provider: provKey,
                      baseUrl: pDef.defaultBaseUrl,
                      model: pDef.defaultModel,
                    }));
                  }}
                >
                  <option value="openai">OpenAI (ChatGPT)</option>
                  <option value="anthropic">Anthropic (Claude)</option>
                  <option value="gemini">Google (Gemini)</option>
                  <option value="custom">Custom / Local LLM (Ollama)</option>
                </select>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                    Active Model
                  </label>
                  {fetchingModels ? (
                    <span style={{ fontSize: '0.7rem', color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                      <RefreshCw className="spinner" size={10} /> Live sync...
                    </span>
                  ) : aiConfig.apiKey ? (
                    <span style={{ fontSize: '0.7rem', color: 'var(--status-success)', fontWeight: 600 }}>
                      Live API List
                    </span>
                  ) : (
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>
                      Standard List
                    </span>
                  )}
                </div>
                <select
                  className="input"
                  style={{ width: '100%', padding: '8px 12px', fontSize: '0.85rem' }}
                  value={aiConfig.model}
                  onChange={(e) => setAiConfig(prev => ({ ...prev, model: e.target.value }))}
                >
                  {availableModels.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Custom Base URL (if Custom provider selected) */}
            {aiConfig.provider === 'custom' && (
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  API Base URL (OpenAI-compatible)
                </label>
                <input
                  type="text"
                  className="input"
                  style={{ width: '100%', padding: '8px 12px', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}
                  value={aiConfig.baseUrl}
                  onChange={(e) => setAiConfig(prev => ({ ...prev, baseUrl: e.target.value }))}
                  placeholder="http://localhost:11434/v1 or https://api.deepseek.com/v1"
                />
              </div>
            )}

            {/* API Key Input */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  API Key
                </label>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>Saved locally in browser RAM/localStorage</span>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="password"
                  className="input"
                  style={{ flex: 1, padding: '8px 12px', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}
                  value={aiConfig.apiKey}
                  onChange={(e) => setAiConfig(prev => ({ ...prev, apiKey: e.target.value }))}
                  placeholder={currentProviderDef.placeholderKey}
                />
                <button
                  type="button"
                  className="btn btn--secondary btn--sm"
                  onClick={handleTestConnection}
                  disabled={testingConnection}
                  style={{ opacity: testingConnection ? 0.7 : 1, cursor: testingConnection ? 'not-allowed' : 'pointer', minWidth: '150px' }}
                >
                  {testingConnection ? <RefreshCw className="spinner" size={14} /> : <Key size={14} />}
                  {testingConnection ? 'Testing...' : 'Test Connection'}
                </button>
              </div>
            </div>

            {/* Connection Testing Progress Card */}
            {testingConnection && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)',
                fontSize: '0.8125rem',
                fontWeight: 600,
                background: 'var(--primary-light)',
                color: 'var(--primary)',
                border: '1px solid var(--primary-border)',
              }}>
                <RefreshCw className="spinner" size={15} style={{ flexShrink: 0 }} />
                <span>Testing API connection to {currentProviderDef.name} ({aiConfig.model})... Please wait.</span>
              </div>
            )}

            {testResult && !testingConnection && (
              <div style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '10px',
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)',
                fontSize: '0.8125rem',
                lineHeight: '1.45',
                background: testResult.success ? 'var(--status-success-bg)' : 'var(--severity-critical-bg)',
                color: testResult.success ? 'var(--status-success)' : 'var(--severity-critical)',
                border: `1px solid ${testResult.success ? 'var(--status-success-border)' : 'var(--severity-critical-border)'}`,
                wordBreak: 'break-word',
                overflowWrap: 'anywhere',
                whiteSpace: 'normal',
              }}>
                {testResult.success ? <CheckCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} /> : <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />}
                <div style={{ flex: 1, minWidth: 0, wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
                  {testResult.message}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Drag & Drop Upload Card */}
      <div
        className={`upload-card ${isDragActive ? 'upload-card--active' : ''}`}
        style={{
          padding: '44px 40px',
          pointerEvents: testingConnection ? 'none' : 'auto',
          opacity: testingConnection ? 0.65 : 1,
          transition: 'all 0.2s ease',
        }}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !testingConnection && folderInputRef.current?.click()}
      >
        <div className="upload-card__icon-wrap" style={{ width: '64px', height: '64px' }}>
          <Upload size={34} />
        </div>

        <h3 className="upload-card__title" style={{ fontSize: '1.4rem' }}>
          Drop your pipeline files or folder
        </h3>
        <p className="upload-card__subtitle" style={{ fontSize: '0.9rem', maxWidth: '440px', marginBottom: '28px' }}>
          Drag DAGs, dbt models, config YAMLs, .env files, or Terraform scripts here for security scanning
        </p>

        <div className="upload-card__actions" onClick={(e) => e.stopPropagation()} style={{ display: 'flex', gap: '12px', marginBottom: '28px' }}>
          <button
            className="btn btn--primary"
            style={{ padding: '12px 24px', fontSize: '0.92rem' }}
            onClick={() => folderInputRef.current?.click()}
          >
            <FolderOpen size={18} />
            Select Folder
          </button>
          <button
            className="btn btn--secondary"
            style={{ padding: '12px 24px', fontSize: '0.92rem' }}
            onClick={() => fileInputRef.current?.click()}
          >
            <FileText size={18} />
            Select Files
          </button>
        </div>

        <div className="upload-card__extensions">
          <span>Supported pipeline formats:</span>
          <div className="ext-pills" style={{ marginTop: '4px' }}>
            <span>.py</span>
            <span>.yaml</span>
            <span>.json</span>
            <span>.toml</span>
            <span>.sql</span>
            <span>.tf</span>
            <span>.env</span>
            <span>.txt</span>
          </div>
        </div>
      </div>

      {/* Privacy Notice Bar */}
      <div className="upload-privacy-bar">
        <Lock size={15} style={{ color: 'var(--status-success)', flexShrink: 0 }} />
        <span>
          <strong>100% Client-Side Privacy Guarantee:</strong> Scanning runs entirely inside your browser's local JavaScript engine. Zero code, credentials, or file bytes leave your computer.
        </span>
      </div>

      {/* Hidden file inputs */}
      <input
        ref={folderInputRef}
        type="file"
        /* @ts-ignore */
        webkitdirectory=""
        directory=""
        multiple
        style={{ display: 'none' }}
        onChange={handleInputChange}
      />
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".py,.yaml,.yml,.json,.toml,.sql,.env,.cfg,.ini,.conf,.sh,.tf,.hcl,.txt,.properties,.xml"
        style={{ display: 'none' }}
        onChange={handleInputChange}
      />
    </div>
  );
}
