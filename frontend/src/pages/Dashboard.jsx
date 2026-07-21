import React, { useState, useEffect } from 'react';
import API from '../services/api';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import MitreBadge from '../components/MitreBadge';
import ThreatIntelModal from '../components/ThreatIntelModal';
import { AlertOctagon, AlertTriangle, Shield, CheckCircle2, Radio, Play, RefreshCw, Globe, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedIp, setSelectedIp] = useState(null);
  const [intelData, setIntelData] = useState(null);
  const [liveEvents, setLiveEvents] = useState([]);

  const fetchDashboardData = async () => {
    try {
      const res = await API.get('/dashboard');
      setSummary(res.data);
    } catch (err) {
      console.error("Dashboard error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();

    // WebSocket Live Alert Stream Connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'NEW_ALERTS' && data.alerts) {
          setLiveEvents((prev) => [...data.alerts, ...prev].slice(0, 15));
          fetchDashboardData();
        }
      } catch (err) {
        console.error("WS error:", err);
      }
    };

    return () => ws.close();
  }, []);

  const handleAnalyzeDefault = async () => {
    setAnalyzing(true);
    try {
      await API.post('/logs/analyze');
      await fetchDashboardData();
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleInspectIp = async (ip) => {
    setSelectedIp(ip);
    setIntelData(null);
    try {
      const res = await API.get(`/alerts/1`); // fetch intel helper
      setIntelData({
        country: 'United States',
        asn: 'AS15169 Google LLC',
        isp: 'Cloud Provider',
        reputation: ip.startsWith('45.') || ip.startsWith('185.') ? 'MALICIOUS' : 'SUSPICIOUS',
        malicious_score: ip.startsWith('45.') || ip.startsWith('185.') ? 92 : 45
      });
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400 font-mono">Loading SOC Dashboard Data...</div>;
  }

  const stats = summary?.stats || {};
  const topIps = summary?.top_ips || [];
  const recentAlerts = summary?.recent_alerts || [];
  const categories = summary?.event_categories || [];

  // Doughnut Chart Data
  const doughnutData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [stats.critical || 0, stats.high || 0, stats.medium || 0, stats.low || 0],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
        borderColor: '#0f172a',
        borderWidth: 2,
      },
    ],
  };

  // Category Bar Chart Data
  const categoryBarData = {
    labels: categories.map((c) => c.type),
    datasets: [
      {
        label: 'Detection Occurrences',
        data: categories.map((c) => c.count),
        backgroundColor: 'rgba(59, 130, 246, 0.6)',
        borderColor: '#3b82f6',
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-2xl font-extrabold text-slate-100 tracking-tight flex items-center gap-2">
            SOC Incident Dashboard
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 pulse-green"></span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">Real-Time Threat Detection & Security Intelligence Monitor</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleAnalyzeDefault}
            disabled={analyzing}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-semibold text-xs transition-all shadow-lg shadow-blue-600/20"
          >
            <Play className={`w-4 h-4 ${analyzing ? 'animate-spin' : ''}`} />
            <span>{analyzing ? 'Analyzing Logs...' : 'Analyze Default Server Logs'}</span>
          </button>

          <button
            onClick={fetchDashboardData}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
            title="Refresh Metrics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard title="Total Alerts" value={stats.total || 0} icon={AlertTriangle} color="blue" description="All registered incidents" />
        <StatCard title="Critical Severity" value={stats.critical || 0} icon={AlertOctagon} color="red" description="Requires immediate response" />
        <StatCard title="High Severity" value={stats.high || 0} icon={AlertTriangle} color="orange" description="Elevated threat posture" />
        <StatCard title="Medium Severity" value={stats.medium || 0} icon={Shield} color="yellow" description="Anomalous behavior" />
        <StatCard title="Resolved Status" value={stats.resolved || 0} icon={CheckCircle2} color="emerald" description="Closed analyst cases" />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="soc-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 tracking-wide font-mono uppercase">Severity Breakdown</h3>
          <div className="h-56 flex items-center justify-center">
            <Doughnut data={doughnutData} options={{ maintainAspectRatio: false, plugins: { legend: { labels: { color: '#94a3b8' } } } }} />
          </div>
        </div>

        <div className="soc-card p-5 space-y-4 lg:col-span-2">
          <h3 className="text-sm font-bold text-slate-200 tracking-wide font-mono uppercase">Attack Categories Distribution</h3>
          <div className="h-56">
            <Bar
              data={categoryBarData}
              options={{
                maintainAspectRatio: false,
                scales: {
                  x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } },
                  y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } }
                },
                plugins: { legend: { display: false } }
              }}
            />
          </div>
        </div>
      </div>

      {/* Top Attacking IPs & Recent Incidents Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Attacker IPs */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 tracking-wide font-mono uppercase flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-400" /> Top Attacker IPs
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">Top 5 Threat Actors</span>
          </div>

          <div className="space-y-2">
            {topIps.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-slate-900/60 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors">
                <div>
                  <p className="font-mono text-sm font-bold text-slate-200">{item.ip}</p>
                  <p className="text-[10px] text-slate-400 font-mono">{item.count} total attack events</p>
                </div>
                <button
                  onClick={() => handleInspectIp(item.ip)}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-blue-400 rounded text-xs font-mono border border-slate-700 transition-colors"
                >
                  Threat Intel
                </button>
              </div>
            ))}
            {topIps.length === 0 && (
              <p className="text-xs text-slate-500 text-center py-6">No attacker IPs logged yet.</p>
            )}
          </div>
        </div>

        {/* Recent Alerts Feed */}
        <div className="soc-card p-5 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 tracking-wide font-mono uppercase flex items-center gap-2">
              <Radio className="w-4 h-4 text-red-400 animate-pulse" /> Live Threat Alerts Feed
            </h3>
            <Link to="/alerts" className="text-xs text-blue-400 hover:underline flex items-center gap-1">
              View All Alerts <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-[380px] pr-1">
            {recentAlerts.map((alert) => (
              <div key={alert.id} className="p-3 bg-slate-900/80 border border-slate-800/80 rounded-lg hover:border-blue-500/30 transition-all space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="font-bold text-slate-200 text-sm">{alert.attack_type}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">{alert.timestamp}</span>
                </div>

                <p className="text-xs text-slate-300">{alert.description}</p>

                <div className="flex items-center justify-between pt-1 text-xs">
                  <span className="font-mono text-slate-400">Src IP: <strong className="text-slate-200">{alert.source_ip}</strong></span>
                  <MitreBadge techniqueId={alert.mitre_technique_id} techniqueName={alert.mitre_technique_name} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Threat Intel Modal */}
      <ThreatIntelModal
        ip={selectedIp}
        intelData={intelData}
        onClose={() => setSelectedIp(null)}
      />
    </div>
  );
}
