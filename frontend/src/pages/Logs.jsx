import React, { useState, useEffect } from 'react';
import API from '../services/api';
import { UploadCloud, FileText, Search, CheckCircle2, AlertCircle, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react';

export default function Logs() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loadingLogs, setLoadingLogs] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  const fetchLogs = async () => {
    setLoadingLogs(true);
    try {
      const res = await API.get('/logs', { params: { page, per_page: 25 } });
      setLogs(res.data.logs);
      setTotalPages(Math.ceil(res.data.total / 25) || 1);
      setTotal(res.data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingLogs(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page]);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setUploadResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await API.post('/logs/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setUploadResult(res.data);
      setFile(null);
      fetchLogs();
    } catch (err) {
      setUploadResult({
        error: err.response?.data?.detail || 'Failed to upload log file.'
      });
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="pb-4 border-b border-slate-800">
        <h2 className="text-2xl font-extrabold text-slate-100 tracking-tight">Log Upload & Ingestion Studio</h2>
        <p className="text-xs text-slate-400 font-mono mt-1">Upload raw log files for instant parsing, threat detection, and storage</p>
      </div>

      {/* Upload Box */}
      <div className="soc-card p-6">
        <form onSubmit={handleUpload} className="flex flex-col items-center justify-center border-2 border-dashed border-slate-700 hover:border-blue-500 rounded-xl p-8 transition-colors bg-slate-900/40 space-y-4">
          <div className="p-4 bg-blue-600/10 border border-blue-500/30 rounded-full text-blue-400">
            <UploadCloud className="w-8 h-8" />
          </div>

          <div className="text-center space-y-1">
            <p className="text-sm font-semibold text-slate-200">
              {file ? file.name : 'Select or drag log file to upload'}
            </p>
            <p className="text-xs text-slate-500 font-mono">Supports: auth.log, syslog, access.log, windows evtx text, json</p>
          </div>

          <input
            type="file"
            onChange={handleFileChange}
            className="hidden"
            id="log-upload-input"
          />

          <div className="flex gap-3">
            <label
              htmlFor="log-upload-input"
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold font-mono cursor-pointer border border-slate-700"
            >
              Browse File
            </label>

            <button
              type="submit"
              disabled={!file || uploading}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold font-mono shadow-lg shadow-blue-600/20"
            >
              {uploading ? 'Processing & Detecting...' : 'Upload & Analyze'}
            </button>
          </div>
        </form>

        {/* Upload Summary Result */}
        {uploadResult && (
          <div className="mt-4 p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            {uploadResult.error ? (
              <div className="text-red-400 text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4" /> {uploadResult.error}
              </div>
            ) : (
              <div className="space-y-2 text-xs font-mono">
                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                  <CheckCircle2 className="w-4 h-4" /> File '{uploadResult.filename}' Parsed Successfully!
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-slate-300">
                  <div>Parsed Events: <strong className="text-blue-400">{uploadResult.parsed}</strong></div>
                  <div>Alerts Generated: <strong className="text-red-400">{uploadResult.alerts}</strong></div>
                  <div>Critical: <strong className="text-red-400">{uploadResult.severity_breakdown?.critical}</strong></div>
                  <div>Log Type: <strong className="text-slate-200">{uploadResult.log_type}</strong></div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Log Explorer Table */}
      <div className="soc-card overflow-hidden">
        <div className="p-4 bg-slate-900/80 border-b border-slate-800 flex justify-between items-center">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-400" /> Processed Log Repository ({total} entries)
          </h3>
          <button onClick={fetchLogs} className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900 text-slate-400 uppercase border-b border-slate-800">
              <tr>
                <th className="p-3">ID</th>
                <th className="p-3">Source File</th>
                <th className="p-3">Event Type</th>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Raw Log Snippet</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/40">
                  <td className="p-3 text-slate-500">#{log.id}</td>
                  <td className="p-3 font-semibold text-blue-400">{log.filename}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px]">
                      {log.event_type}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                  <td className="p-3 truncate max-w-md text-slate-300">{log.raw_log}</td>
                </tr>
              ))}
              {logs.length === 0 && !loadingLogs && (
                <tr>
                  <td colSpan="5" className="p-8 text-center text-slate-500">No log entries found in repository.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="p-4 bg-slate-900/60 border-t border-slate-800 flex justify-between items-center text-xs font-mono text-slate-400">
          <span>Page {page} of {totalPages}</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              className="p-1 bg-slate-800 rounded disabled:opacity-50"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
              className="p-1 bg-slate-800 rounded disabled:opacity-50"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
