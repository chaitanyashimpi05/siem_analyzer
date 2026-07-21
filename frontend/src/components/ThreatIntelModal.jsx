import React from 'react';
import { X, ShieldAlert, Globe, Server, AlertTriangle } from 'lucide-react';

export default function ThreatIntelModal({ ip, intelData, onClose }) {
  if (!ip) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
      <div className="soc-card-glow max-w-md w-full p-6 space-y-5 relative animate-in fade-in zoom-in duration-200">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-slate-100 font-mono">Threat Intelligence</h3>
            <p className="text-xs text-slate-400 font-mono">IP Address: {ip}</p>
          </div>
        </div>

        {intelData ? (
          <div className="space-y-4 text-sm">
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-3">
              <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                <span className="text-slate-400 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-blue-400" /> Geolocation / Country
                </span>
                <span className="font-semibold text-slate-200">{intelData.country || 'Unknown'}</span>
              </div>

              <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                <span className="text-slate-400 flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-400" /> ASN & Network
                </span>
                <span className="font-mono text-xs text-slate-300 truncate max-w-[200px]">{intelData.asn || 'N/A'}</span>
              </div>

              <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                <span className="text-slate-400">ISP Provider</span>
                <span className="font-semibold text-slate-200">{intelData.isp || 'N/A'}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-slate-400">Reputation Level</span>
                <span className={`px-2 py-0.5 rounded font-mono font-bold text-xs ${
                  intelData.reputation === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                  intelData.reputation === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                  'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                }`}>
                  {intelData.reputation}
                </span>
              </div>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-xs text-slate-400">AbuseIPDB Confidence Score</span>
                <span className="font-mono font-bold text-sm text-red-400">{intelData.malicious_score || 0}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-red-500 h-full transition-all"
                  style={{ width: `${intelData.malicious_score || 0}%` }}
                ></div>
              </div>
            </div>
          </div>
        ) : (
          <div className="py-8 text-center text-slate-400 font-mono">Loading Threat Intelligence data...</div>
        )}

        <button
          onClick={onClose}
          className="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-semibold text-sm transition-colors"
        >
          Close Assessment
        </button>
      </div>
    </div>
  );
}
