import React, { useState, useEffect } from 'react';
import API from '../services/api';
import { BarChart3, Download, FileText, CheckCircle2, Clock } from 'lucide-react';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [reportType, setReportType] = useState('PDF');

  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await API.get('/reports');
      setReports(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleGenerate = async (type) => {
    setGenerating(true);
    try {
      await API.post('/reports/generate', { report_type: type });
      fetchReports();
    } catch (err) {
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="pb-4 border-b border-slate-800">
        <h2 className="text-2xl font-extrabold text-slate-100 tracking-tight">Executive Security Reporting</h2>
        <p className="text-xs text-slate-400 font-mono mt-1">Compile comprehensive incident metrics, attack timelines, and MITRE ATT&CK mitigation reports</p>
      </div>

      {/* Generation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 font-mono">PDF Executive Report</h3>
              <p className="text-xs text-slate-400 font-mono">Formal document designed for CISO & Leadership review</p>
            </div>
          </div>
          <p className="text-xs text-slate-300">Contains high-level summary graphs, top 5 attacker IP addresses, MITRE ATT&CK matrix, and recommended mitigation actions.</p>
          <button
            onClick={() => handleGenerate('PDF')}
            disabled={generating}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-semibold text-xs font-mono transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20"
          >
            <Download className="w-4 h-4" />
            <span>{generating ? 'Generating PDF...' : 'Generate PDF Security Report'}</span>
          </button>
        </div>

        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-xl text-blue-400">
              <BarChart3 className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 font-mono">Interactive HTML Report</h3>
              <p className="text-xs text-slate-400 font-mono">Web document suitable for SOC analyst deep dive</p>
            </div>
          </div>
          <p className="text-xs text-slate-300">Dynamic dark-mode web page detailing raw incident payloads, severity breakdowns, and threat actor IP distributions.</p>
          <button
            onClick={() => handleGenerate('HTML')}
            disabled={generating}
            className="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg font-semibold text-xs font-mono transition-all flex items-center justify-center gap-2"
          >
            <Download className="w-4 h-4 text-blue-400" />
            <span>{generating ? 'Generating HTML...' : 'Generate Interactive HTML Report'}</span>
          </button>
        </div>
      </div>

      {/* Generated Reports Table */}
      <div className="soc-card overflow-hidden">
        <div className="p-4 bg-slate-900/80 border-b border-slate-800">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase">Generated Report Archive</h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900 text-slate-400 uppercase border-b border-slate-800">
              <tr>
                <th className="p-3">ID</th>
                <th className="p-3">Filename</th>
                <th className="p-3">Format</th>
                <th className="p-3">Generated At</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {reports.map((report) => (
                <tr key={report.id} className="hover:bg-slate-800/40">
                  <td className="p-3 text-slate-500">#{report.id}</td>
                  <td className="p-3 font-semibold text-slate-200">{report.filename}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                      report.report_type === 'PDF' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}>
                      {report.report_type}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400">{new Date(report.generated_at).toLocaleString()}</td>
                  <td className="p-3 text-right">
                    <a
                      href={report.download_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-blue-400 border border-slate-700 rounded transition-colors inline-flex items-center gap-1"
                    >
                      <Download className="w-3.5 h-3.5" /> Download
                    </a>
                  </td>
                </tr>
              ))}
              {reports.length === 0 && !loading && (
                <tr>
                  <td colSpan="5" className="p-8 text-center text-slate-500">No reports generated yet. Click above to generate your first security report.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
