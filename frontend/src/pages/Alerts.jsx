import React, { useState, useEffect } from 'react';
import API from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import MitreBadge from '../components/MitreBadge';
import ThreatIntelModal from '../components/ThreatIntelModal';
import { Search, Download, Filter, CheckCircle, ShieldOff, Eye, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  // Filters
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedIp, setSelectedIp] = useState(null);
  const [intelData, setIntelData] = useState(null);
  const [notesModalAlert, setNotesModalAlert] = useState(null);
  const [analystNotes, setAnalystNotes] = useState('');

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const res = await API.get('/alerts', {
        params: {
          page,
          per_page: 20,
          search: search || undefined,
          severity: severity || undefined,
          status: statusFilter || undefined,
        }
      });
      setAlerts(res.data.alerts);
      setTotalPages(res.data.total_pages);
      setTotal(res.data.total);
    } catch (err) {
      console.error("Fetch alerts error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, severity, statusFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchAlerts();
  };

  const handleExportCsv = () => {
    window.open('/api/alerts/export/csv', '_blank');
  };

  const handleUpdateStatus = async (alertId, newStatus) => {
    try {
      await API.patch(`/alerts/${alertId}`, { status: newStatus });
      fetchAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveNotes = async () => {
    if (!notesModalAlert) return;
    try {
      await API.patch(`/alerts/${notesModalAlert.id}`, { analyst_notes: analystNotes });
      setNotesModalAlert(null);
      fetchAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleInspectIp = (ip) => {
    setSelectedIp(ip);
    setIntelData({
      country: 'United States',
      asn: 'AS15169 Google LLC',
      isp: 'Cloud Network Provider',
      reputation: ip.startswith?.('45.') || ip.startswith?.('185.') ? 'MALICIOUS' : 'SUSPICIOUS',
      malicious_score: ip.startswith?.('45.') || ip.startswith?.('185.') ? 88 : 35
    });
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-2xl font-extrabold text-slate-100 tracking-tight">Security Alert Management Center</h2>
          <p className="text-xs text-slate-400 font-mono mt-1">Review, triage, and take action on detected security incidents ({total} total)</p>
        </div>

        <button
          onClick={handleExportCsv}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold font-mono transition-colors"
        >
          <Download className="w-4 h-4 text-blue-400" /> Export Alerts to CSV
        </button>
      </div>

      {/* Filter Bar */}
      <div className="soc-card p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Search by IP, attack type, description, or MITRE ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none"
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold font-mono"
            >
              Search
            </button>
          </div>
        </form>
      </div>

      {/* Alerts Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-900/90 text-xs font-mono uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-4">Timestamp</th>
                <th className="p-4">Severity</th>
                <th className="p-4">Attack Type</th>
                <th className="p-4">Source IP</th>
                <th className="p-4">MITRE Technique</th>
                <th className="p-4">Status</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {alerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="p-4 font-mono text-xs text-slate-400 whitespace-nowrap">{alert.timestamp}</td>
                  <td className="p-4"><SeverityBadge severity={alert.severity} /></td>
                  <td className="p-4 font-bold text-slate-200">{alert.attack_type}</td>
                  <td className="p-4 font-mono">
                    <button
                      onClick={() => handleInspectIp(alert.source_ip)}
                      className="text-blue-400 hover:underline"
                    >
                      {alert.source_ip}
                    </button>
                  </td>
                  <td className="p-4">
                    <MitreBadge techniqueId={alert.mitre_technique_id} techniqueName={alert.mitre_technique_name} />
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      alert.status === 'OPEN' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                      alert.status === 'RESOLVED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {alert.status}
                    </span>
                  </td>
                  <td className="p-4 text-right space-x-1 whitespace-nowrap">
                    {alert.status === 'OPEN' && (
                      <>
                        <button
                          onClick={() => handleUpdateStatus(alert.id, 'RESOLVED')}
                          className="px-2 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded text-xs border border-emerald-500/30 font-mono"
                          title="Mark Resolved"
                        >
                          Resolve
                        </button>
                        <button
                          onClick={() => handleUpdateStatus(alert.id, 'FALSE_POSITIVE')}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded text-xs border border-slate-700 font-mono"
                          title="Mark False Positive"
                        >
                          FP
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => { setNotesModalAlert(alert); setAnalystNotes(alert.analyst_notes || ''); }}
                      className="px-2 py-1 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 rounded text-xs border border-blue-500/30 font-mono"
                      title="Analyst Notes"
                    >
                      Notes
                    </button>
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && !loading && (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-slate-500 font-mono">
                    No security alerts matched the selected filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Page {page} of {totalPages} ({total} alerts)</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              className="p-1.5 bg-slate-800 rounded hover:bg-slate-700 disabled:opacity-50"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
              className="p-1.5 bg-slate-800 rounded hover:bg-slate-700 disabled:opacity-50"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Analyst Notes Modal */}
      {notesModalAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="soc-card-glow max-w-lg w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-slate-100 font-mono">Analyst Notes & Triaging</h3>
            <p className="text-xs text-slate-400 font-mono">Alert: {notesModalAlert.attack_type} (ID: {notesModalAlert.id})</p>
            <textarea
              rows="4"
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Add investigation findings, mitigation steps, or notes..."
              className="w-full p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setNotesModalAlert(null)}
                className="px-4 py-2 bg-slate-800 text-slate-300 rounded text-xs font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveNotes}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-semibold"
              >
                Save Notes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Threat Intel Modal */}
      <ThreatIntelModal
        ip={selectedIp}
        intelData={intelData}
        onClose={() => setSelectedIp(null)}
      />
    </div>
  );
}
