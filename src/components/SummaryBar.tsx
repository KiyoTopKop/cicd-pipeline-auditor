import { motion } from 'framer-motion';
import type { AnalysisResult } from '../engine/types';

interface SummaryBarProps {
  result: AnalysisResult | null;
  onCopyJSON: () => void;
  onCopySARIF: () => void;
  onJumpToSeverity: (severity: string) => void;
}

export function SummaryBar({ result, onCopyJSON, onCopySARIF, onJumpToSeverity }: SummaryBarProps) {
  const counts = result?.findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>) || {};

  const riskScore = result?.riskScore || 0;

  return (
    <div className="summary-bar">
      <div className="stat-item">
        <span className="stat-label">RISK ATTESTATION</span>
        <div className="risk-score-container" style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
          <motion.span 
            key={riskScore}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="risk-level"
          >
            {result ? riskScore.toFixed(1) : '--.-'}
          </motion.span>
          <span className="stat-label" style={{ fontSize: '0.6rem' }}>/ 10.0</span>
        </div>
      </div>

      <div className="stat-item" style={{ marginLeft: 24 }}>
        <span className="stat-label">THREAT_VECTORS</span>
        <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
            const count = counts[sev] || 0;
            return (
              <motion.button
                key={sev}
                whileHover={count > 0 ? { y: -2, backgroundColor: 'rgba(255,255,255,0.1)' } : {}}
                whileTap={count > 0 ? { y: 0 } : {}}
                className={`severity-pill ${sev}`}
                onClick={() => count > 0 && onJumpToSeverity(sev)}
                style={{ 
                  opacity: count > 0 ? 1 : 0.2,
                  cursor: count > 0 ? 'pointer' : 'default'
                }}
              >
                {sev.substring(0, 1)}:{count}
              </motion.button>
            );
          })}
        </div>
      </div>

      <div className="stat-item" style={{ marginLeft: 'auto', flexDirection: 'row', gap: 12, alignItems: 'center' }}>
        <button className="btn" onClick={onCopyJSON} disabled={!result}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
          </svg>
          REPORT.JSON
        </button>
        <button className="btn" onClick={onCopySARIF} disabled={!result}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          SARIF
        </button>
      </div>
    </div>
  );
}
