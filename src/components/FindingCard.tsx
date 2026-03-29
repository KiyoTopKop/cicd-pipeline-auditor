import { motion, AnimatePresence } from 'framer-motion';
import type { Finding } from '../engine/types';

interface FindingCardProps {
  finding: Finding;
  isExpanded: boolean;
  onToggle: () => void;
}

export function FindingCard({ finding, isExpanded, onToggle }: FindingCardProps) {
  const cardClass = `finding-card ${isExpanded ? 'selected' : ''}`;

  return (
    <motion.div 
      layout
      id={`finding-${finding.id}`} 
      className={cardClass} 
      onClick={onToggle}
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
    >
      <div className="finding-header">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="finding-rule-id">{finding.ruleDef.cwe}</span>
            <span className="logo-version" style={{ fontSize: '0.6rem', opacity: 0.5 }}>{finding.ruleId}</span>
          </div>
          <div className="finding-title">{finding.ruleDef.shortDescription}</div>
        </div>
        <div className={`severity-pill ${finding.severity}`} style={{ alignSelf: 'flex-start' }}>
          {finding.severity}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, opacity: 0.4, fontSize: '0.7rem' }}>
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M4 17l6-6-6-6M12 19h8" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        <span style={{ fontFamily: 'var(--font-mono)' }}>LINE {finding.line} : {finding.context}</span>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{ paddingTop: 16, borderTop: '1px solid var(--border-subtle)', marginTop: 12 }}>
              <p style={{ fontSize: '0.8rem', opacity: 0.7, lineHeight: 1.5, marginBottom: 16 }}>
                {finding.message}
              </p>

              <div className="glass-panel" style={{ borderRadius: 8, overflow: 'hidden', background: 'rgba(0,0,0,0.2)' }}>
                <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', fontSize: '0.65rem', fontWeight: 700, opacity: 0.4 }}>
                  REMEDIATION_DIFF
                </div>
                <div style={{ padding: 12, fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                  <div style={{ color: 'var(--critical)', display: 'flex', gap: 8, marginBottom: 4 }}>
                    <span style={{ opacity: 0.5 }}>-</span>
                    <span>{finding.ruleDef.remediation.before}</span>
                  </div>
                  <div style={{ color: 'var(--success)', display: 'flex', gap: 8 }}>
                    <span style={{ opacity: 0.5 }}>+</span>
                    <span>{finding.ruleDef.remediation.after}</span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
                <button 
                  className="btn btn-primary" 
                  style={{ fontSize: '0.7rem', padding: '6px 12px' }}
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(finding.ruleDef.remediation.after);
                  }}
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                  </svg>
                  Copy
                </button>
                {finding.ruleDef.references.map((url, i) => (
                  <a 
                    key={i} 
                    href={url} 
                    target="_blank" 
                    rel="noopener noreferrer" 
                    className="btn" 
                    style={{ fontSize: '0.7rem', padding: '6px 12px' }}
                    onClick={e => e.stopPropagation()}
                  >
                    REF_{i + 1}
                  </a>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
