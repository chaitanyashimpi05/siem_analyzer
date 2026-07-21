import React from 'react';

export default function SeverityBadge({ severity }) {
  const sev = (severity || 'INFO').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40 pulse-red',
    HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
    INFO: 'bg-slate-700/50 text-slate-300 border-slate-600',
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-bold font-mono border ${styles[sev] || styles.INFO}`}>
      {sev}
    </span>
  );
}
