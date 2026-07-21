import React from 'react';
import { useAuth } from '../services/authContext';
import { Shield, Bell, User, LogOut, Radio } from 'lucide-react';

export default function Navbar({ liveAlertCount = 0 }) {
  const { user, logout } = useAuth();

  return (
    <header className="h-16 bg-slate-900/90 border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-lg text-blue-400">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <h1 className="font-bold text-lg text-slate-100 tracking-wide flex items-center gap-2">
            AETHER <span className="text-blue-500 text-xs px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 font-mono">SOC SIEM v2.0</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono">Autonomous Threat Detection & Security Engine</p>
        </div>
      </div>

      <div className="flex items-center gap-5">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700 text-xs text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-500 pulse-green"></span>
          <span className="font-mono">SYSTEM ACTIVE</span>
        </div>

        {liveAlertCount > 0 && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-semibold animate-pulse">
            <Radio className="w-4 h-4 text-red-500" />
            <span>{liveAlertCount} NEW ALERTS</span>
          </div>
        )}

        {user && (
          <div className="flex items-center gap-3 pl-4 border-l border-slate-800">
            <div className="text-right">
              <p className="text-xs font-semibold text-slate-200">{user.username}</p>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 bg-blue-500/20 text-blue-400 rounded">
                {user.role || 'Analyst'}
              </span>
            </div>
            <button
              onClick={logout}
              title="Logout"
              className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
