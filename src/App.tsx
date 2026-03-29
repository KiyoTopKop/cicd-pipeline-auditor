import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Editor } from './components/Editor';
import { Results } from './components/Results';
import { SummaryBar } from './components/SummaryBar';
import { analyze, toJSON, toSARIF } from './engine/analyzer';
import type { AnalysisResult } from './engine/types';
import defaultWorkflow from './data/example-workflow.yaml?raw';

export default function App() {
  const [yamlContent, setYamlContent] = useState<string>(defaultWorkflow);
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const runAudit = useCallback(() => {
    setIsScanning(true);
    setResult(null);
    setSelectedFindingId(null);

    // Simulate slight network delay for the premium scanning effect
    setTimeout(() => {
      const res = analyze(yamlContent);
      setResult(res);
      setIsScanning(false);
      if (res.findings.length > 0) {
        setSelectedFindingId(res.findings[0].id);
      }
    }, 1200); // Longer delay (1.2s) for a more cinematic feel
  }, [yamlContent]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        runAudit();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [runAudit]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const handleCopyJSON = () => {
    if (!result) return;
    navigator.clipboard.writeText(toJSON(result));
    showToast('JSON REPORT COPIED');
  };

  const handleCopySARIF = () => {
    if (!result) return;
    navigator.clipboard.writeText(toSARIF(result));
    showToast('SARIF REPORT COPIED');
  };

  const handleJumpToSeverity = (severity: string) => {
    if (!result) return;
    const firstMatch = result.findings.find(f => f.severity === severity);
    if (firstMatch) {
      setSelectedFindingId(firstMatch.id);
      const element = document.getElementById(`finding-${firstMatch.id}`);
      element?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <div className="app-layout">
      <AnimatePresence>
        {toastMessage && (
          <motion.div 
            initial={{ y: -50, x: '-50%', opacity: 0 }}
            animate={{ y: 0, x: '-50%', opacity: 1 }}
            exit={{ y: -50, x: '-50%', opacity: 0 }}
            className="copy-feedback"
          >
            {toastMessage}
          </motion.div>
        )}
      </AnimatePresence>

      <header className="header">
        <div className="header-logo">
          <div className="logo-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <span className="logo-text">PIPELINT</span>
          <span className="logo-version">PRO v1.5</span>
        </div>

        <div className="audit-btn-wrapper">
          <button 
            className="btn btn-primary" 
            onClick={runAudit} 
            disabled={isScanning || !yamlContent.trim()}
          >
            {isScanning ? (
              <>
                <motion.span
                  animate={{ opacity: [1, 0.5, 1] }}
                  transition={{ repeat: Infinity, duration: 1 }}
                >
                  ANALYZING...
                </motion.span>
              </>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                </svg>
                RUN AUDIT
              </>
            )}
          </button>
        </div>

        <div className="header-actions">
           <div className="severity-pill" style={{ borderColor: 'var(--success)', color: 'var(--success)', background: 'rgba(48, 209, 88, 0.1)' }}>
             SECURE_SANDBOX
           </div>
        </div>
      </header>

      <SummaryBar 
        result={result} 
        onCopyJSON={handleCopyJSON} 
        onCopySARIF={handleCopySARIF} 
        onJumpToSeverity={handleJumpToSeverity}
      />

      <div className="split-panel">
        <motion.div 
          layout
          className="panel-editor"
        >
          <div className="editor-toolbar">
              <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                <div className="stat-label">COMPONENT</div>
                <div style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>workflow.yml</div>
              </div>
              <div className="stat-label" style={{ opacity: 0.3 }}>LINT_READY</div>
          </div>
          <div className="editor-wrapper" style={{ flex: 1, position: 'relative' }}>
            <AnimatePresence>
              {isScanning && (
                 <motion.div 
                   initial={{ opacity: 0 }}
                   animate={{ opacity: 1 }}
                   exit={{ opacity: 0 }}
                   className="scan-overlay"
                 >
                   <div className="scan-line" />
                 </motion.div>
              )}
            </AnimatePresence>
            <Editor 
              value={yamlContent} 
              onChange={val => setYamlContent(val ?? '')} 
              findings={result?.findings ?? []}
              selectedFindingId={selectedFindingId}
              onSelectFinding={setSelectedFindingId}
            />
          </div>
        </motion.div>
        
        <Results 
          result={result} 
          selectedFindingId={selectedFindingId}
          onSelectFinding={setSelectedFindingId}
        />
      </div>
    </div>
  );
}
