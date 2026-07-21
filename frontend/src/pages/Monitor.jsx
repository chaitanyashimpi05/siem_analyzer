import React, { useState, useEffect } from 'react';
import API from '../services/api';
import { Activity, Play, Square, CheckCircle2, AlertOctagon, Radio } from 'lucide-react';

export default function Monitor() {
  const [active, setActive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [streamLogs, setStreamLogs] = useState([]);

  const checkStatus = async () => {
    try {
      const res = await API.get('/monitor/status');
      setActive(res.data.active);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkStatus();

    // Listen to live alerts
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'NEW_ALERTS') {
          const timestamp = new Date().toLocaleTimeString();
          const logEntry = `[${timestamp}] [WATCHDOG EVENT] Auto-parsed new log file. Generated ${data.count} alert(s).`;
          setStreamLogs((prev) => [logEntry, ...prev]);
        }
      } catch (err) {
        console.error(err);
      }
    };

    return () => ws.close();
  }, []);

  const handleStart = async () => {
    try {
      await API.post('/monitor/start');
      setActive(true);
    } catch (err) {
      console.error(err);
    }
  };

  const handleStop = async () => {
    try {
      await API.post('/monitor/stop');
      setActive(false);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="pb-4 border-b border-slate-800">
        <h2 className="text-2xl font-extrabold text-slate-100 tracking-tight">Real-Time Directory Monitor</h2>
        <p className="text-xs text-slate-400 font-mono mt-1">Automated Watchdog service monitoring system directory for incoming log files</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Status Card */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase font-mono">Service Status</span>
            <Activity className="w-5 h-5 text-blue-400" />
          </div>

          <div className="flex items-center gap-3">
            <span className={`w-4 h-4 rounded-full ${active ? 'bg-emerald-500 pulse-green' : 'bg-red-500'}`}></span>
            <span className="text-xl font-bold font-mono text-slate-100">{active ? 'MONITORING ACTIVE' : 'STOPPED'}</span>
          </div>

          <p className="text-xs text-slate-400 font-mono">Target Directory: <strong className="text-slate-200">logs/</strong></p>

          <div className="pt-2 flex gap-3">
            {!active ? (
              <button
                onClick={handleStart}
                className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold text-xs font-mono transition-all flex items-center justify-center gap-2"
              >
                <Play className="w-4 h-4" /> Start Watchdog
              </button>
            ) : (
              <button
                onClick={handleStop}
                className="w-full py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-lg font-semibold text-xs font-mono transition-all flex items-center justify-center gap-2"
              >
                <Square className="w-4 h-4" /> Stop Watchdog
              </button>
            )}
          </div>
        </div>

        {/* Feature Specs */}
        <div className="soc-card p-6 space-y-3 md:col-span-2">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase">Automated Pipeline Capabilities</h3>
          <ul className="space-y-2 text-xs text-slate-300 font-mono">
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Instant file creation & modification detection in <code className="text-blue-400">logs/</code>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Automatic format classifier (Linux auth.log, Syslog, Apache, Windows Event, JSON)
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Real-time execution of 16 threat detection rules with MITRE ATT&CK tagging
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Zero-refresh WebSocket broadcast straight to SOC analyst console
            </li>
          </ul>
        </div>
      </div>

      {/* Live Event Stream Terminal */}
      <div className="soc-card p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase flex items-center gap-2">
            <Radio className="w-4 h-4 text-red-400 animate-pulse" /> Live Event Observer Stream
          </h3>
          <span className="text-[10px] text-slate-500 font-mono">WebSocket Channel: /ws/alerts</span>
        </div>

        <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-emerald-400 min-h-[220px] max-h-[300px] overflow-y-auto space-y-1">
          <p className="text-slate-500">[SYSTEM] Watchdog observer feed attached...</p>
          {streamLogs.map((log, idx) => (
            <p key={idx} className="text-emerald-400">{log}</p>
          ))}
          {streamLogs.length === 0 && (
            <p className="text-slate-600">Waiting for log file activity in 'logs/' directory...</p>
          )}
        </div>
      </div>
    </div>
  );
}
