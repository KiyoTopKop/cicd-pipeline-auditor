import { motion, AnimatePresence } from 'framer-motion';
import type { AnalysisResult } from '../engine/types';
import { FindingCard } from './FindingCard';

interface ResultsProps {
  result: AnalysisResult | null;
  selectedFindingId: string | null;
  onSelectFinding: (id: string | null) => void;
}

export function Results({ result, selectedFindingId, onSelectFinding }: ResultsProps) {
  if (!result) {
    return (
      <div className="panel-results">
        <div style={{ flex: 1, display: 'grid', placeItems: 'center', opacity: 0.3 }}>
          <div style={{ textAlign: 'center' }}>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, marginTop: 16 }}>READY_FOR_SCAN</div>
            <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>CTRL+ENTER TO BEGIN</div>
          </div>
        </div>
      </div>
    );
  }

  if (result.findings.length === 0) {
    return (
      <div className="panel-results">
        <div style={{ flex: 1, display: 'grid', placeItems: 'center' }}>
          <motion.div 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            style={{ textAlign: 'center' }}
          >
            <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(48, 209, 88, 0.1)', display: 'grid', placeItems: 'center', margin: '0 auto 24px', color: 'var(--success)' }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                <path d="M20 6L9 17l-5-5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 800 }}>ZERO_THREATS</div>
            <div style={{ fontSize: '0.75rem', opacity: 0.5, marginTop: 4 }}>WORKFLOW_ATTESTATION_PASSED</div>
          </motion.div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel-results">
      <div className="results-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span>THREAT_LOG</span>
          <span className="logo-version" style={{ fontWeight: 800 }}>{result.findings.length}</span>
        </div>
        <div style={{ fontSize: '0.65rem', opacity: 0.4 }}>REAL_TIME_MONITOR</div>
      </div>
      <div className="results-body">
        <AnimatePresence>
          {result.findings.map((finding, idx) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              isExpanded={selectedFindingId === finding.id}
              onToggle={() => onSelectFinding(selectedFindingId === finding.id ? null : finding.id)}
            />
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
