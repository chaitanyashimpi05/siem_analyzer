import React from 'react';

export default function StatCard({ title, value, icon: Icon, color = 'blue', description }) {
  const colorMap = {
    red: 'border-red-500/30 text-red-400 bg-red-500/10 shadow-red-500/5',
    orange: 'border-orange-500/30 text-orange-400 bg-orange-500/10 shadow-orange-500/5',
    yellow: 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10 shadow-yellow-500/5',
    blue: 'border-blue-500/30 text-blue-400 bg-blue-500/10 shadow-blue-500/5',
    emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10 shadow-emerald-500/5',
  };

  return (
    <div className={`p-5 rounded-xl soc-card border transition-all hover:scale-[1.02] shadow-xl ${colorMap[color]}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
        {Icon && <Icon className="w-5 h-5 opacity-80" />}
      </div>
      <div className="mt-3 text-3xl font-extrabold font-mono tracking-tight text-slate-100">
        {value}
      </div>
      {description && (
        <p className="mt-1 text-xs text-slate-500">{description}</p>
      )}
    </div>
  );
}
