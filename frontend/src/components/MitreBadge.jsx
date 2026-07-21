import React from 'react';
import { ExternalLink } from 'lucide-react';

export default function MitreBadge({ techniqueId, techniqueName, tactic }) {
  if (!techniqueId) return null;

  const mitreUrl = `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}`;

  return (
    <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300">
      <span className="text-blue-400 font-semibold">{techniqueId}</span>
      {techniqueName && <span className="text-slate-400 truncate max-w-[150px]">{techniqueName}</span>}
      <a
        href={mitreUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="text-slate-500 hover:text-blue-400 ml-0.5"
        title="View on MITRE ATT&CK Framework"
      >
        <ExternalLink className="w-3 h-3" />
      </a>
    </div>
  );
}
