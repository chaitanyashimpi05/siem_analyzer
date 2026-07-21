import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, AlertTriangle, FileText, Activity, BarChart3, Settings } from 'lucide-react';

export default function Sidebar() {
  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Alert Center', path: '/alerts', icon: AlertTriangle },
    { name: 'Log Studio', path: '/logs', icon: FileText },
    { name: 'Real-Time Monitor', path: '/monitor', icon: Activity },
    { name: 'Reports', path: '/reports', icon: BarChart3 },
  ];

  return (
    <aside className="w-64 bg-slate-900/60 border-r border-slate-800 flex flex-col justify-between p-4 sticky top-16 h-[calc(100vh-4rem)]">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
          SOC NAVIGATION
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-lg shadow-blue-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              <span>{item.name}</span>
            </NavLink>
          );
        })}
      </div>

      <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span>Engine Status</span>
          <span className="text-emerald-400 font-mono font-semibold">ONLINE</span>
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div className="bg-blue-500 h-full w-[94%] animate-pulse"></div>
        </div>
        <p className="text-[10px] text-slate-500 font-mono">SOC Node: us-east-siem01</p>
      </div>
    </aside>
  );
}
