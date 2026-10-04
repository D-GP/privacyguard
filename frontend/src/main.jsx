import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ShieldCheck, LayoutDashboard, ScanSearch, History, FileText, LogOut, Menu, X, Activity, LockKeyhole } from 'lucide-react';
import { api } from './services/api';
import './styles/app.css';

function Auth({ onAuth }) {
  const [mode, setMode] = useState('login'); const [form, setForm] = useState({ name: '', email: '', password: '' }); const [error, setError] = useState('');
  const submit = async e => { e.preventDefault(); setError(''); try { const r = mode === 'login' ? await api.login(form) : await api.register(form); localStorage.setItem('pg_token', r.token); onAuth(r.user) } catch (x) { setError(x.message) } };
  return <div className="auth-shell"><div className="auth-art"><div className="brand"><ShieldCheck size={28} /> PrivacyGuard AI</div><h1>Privacy by design.<br /><span>Intelligence with control.</span></h1><p>Detect sensitive information, understand re-identification risk, and transform data safely before it reaches downstream systems.</p><div className="security-pills"><span>Hybrid PII detection</span><span>Risk-aware anonymization</span><span>Audit-ready</span></div></div><div className="auth-card"><div className="auth-head"><div className="logo-mini"><ShieldCheck size={22} /></div><h2>{mode === 'login' ? 'Welcome back' : 'Create your workspace'}</h2><p>{mode === 'login' ? 'Sign in to your privacy workspace.' : 'Start building safer data workflows.'}</p></div>{error && <div className="error">{error}</div>}<form onSubmit={submit}>{mode === 'register' && <label>Full name<input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required /></label>}<label>Email<input type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} required /></label><label>Password<input type="password" minLength="8" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} required /></label><button className="primary full">{mode === 'login' ? 'Sign in' : 'Create account'}</button></form><button className="link-btn" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError('') }}>{mode === 'login' ? "Don't have an account? Create one" : "Already have an account? Sign in"}</button></div></div>
}

function App() {
  const [user, setUser] = useState(null); const [page, setPage] = useState('dashboard'); const [mobile, setMobile] = useState(false);
  useEffect(() => { if (localStorage.getItem('pg_token')) api.me().then(setUser).catch(() => localStorage.removeItem('pg_token')) }, []);
  if (!user) return <Auth onAuth={setUser} />;
  const logout = () => { localStorage.removeItem('pg_token'); setUser(null) };
  const nav = [['dashboard', 'Dashboard', LayoutDashboard], ['analyze', 'New Analysis', ScanSearch], ['history', 'Scan History', History], ['audit', 'Audit Trail', LockKeyhole]];
  return <div className="app"><aside className={mobile ? 'sidebar open' : 'sidebar'}><div className="sidebar-brand"><ShieldCheck size={27} /><span>PrivacyGuard <b>AI</b></span><button className="icon mobile-close" onClick={() => setMobile(false)}><X /></button></div><nav>{nav.map(([id, label, Icon]) => <button key={id} className={page === id ? 'nav-item active' : 'nav-item'} onClick={() => { setPage(id); setMobile(false) }}><Icon size={18} />{label}</button>)}</nav><div className="sidebar-bottom"><div className="user-mini"><div className="avatar">{user.name[0]}</div><div><b>{user.name}</b><small>{user.role}</small></div></div><button className="nav-item" onClick={logout}><LogOut size={18} />Sign out</button></div></aside><main className="main"><header className="topbar"><button className="icon mobile-menu" onClick={() => setMobile(true)}><Menu /></button><div><span className="eyebrow">SECURE DATA WORKSPACE</span><h1>{nav.find(x => x[0] === page)?.[1]}</h1></div><div className="top-status"><span className="status-dot"></span>Local analysis ready</div></header><section className="content">{page === 'dashboard' && <Dashboard />}{page === 'analyze' && <Analyzer />}{page === 'history' && <HistoryPage />}{page === 'audit' && <AuditPage />}</section></main></div>
}

function Dashboard() { const [d, setD] = useState(null); const [scans, setScans] = useState([]); useEffect(() => { Promise.all([api.dashboard(), api.scans()]).then(([a, b]) => { setD(a); setScans(b.slice(0, 5)) }) }, []); if (!d) return <Loading />; return <><div className="hero"><div><span className="tag">PRIVACY INTELLIGENCE</span><h2>Understand your data before it leaves your control.</h2><p>PrivacyGuard combines deterministic patterns, NLP detection, contextual analysis and risk-aware de-identification.</p></div><div className="hero-icon"><ShieldCheck size={48} /></div></div><div className="stats"><Stat label="Total scans" value={d.total_scans} /><Stat label="High-risk scans" value={d.high_risk_scans} /><Stat label="Average risk" value={`${d.average_risk}%`} /><Stat label="Entities found" value={d.entities_found} /></div><div className="grid-2"><div className="panel"><div className="panel-title"><div><h3>Risk distribution</h3><p>Across your recent workspace scans</p></div></div><div className="bars">{Object.entries(d.risk_distribution).map(([k, v]) => <div className="bar-row" key={k}><span>{k}</span><div className="bar"><i style={{ width: `${Math.min(100, v * 20)}%` }}></i></div><b>{v}</b></div>)}</div></div><div className="panel"><div className="panel-title"><div><h3>Recent scans</h3><p>Latest privacy assessments</p></div></div>{scans.length ? <div className="scan-list">{scans.map(s => <div className="scan-row" key={s.id}><div><b>{s.title}</b><small>{new Date(s.created_at).toLocaleString()}</small></div><Risk level={s.risk_level} score={s.risk_score} /></div>)}</div> : <Empty text="No scans yet. Start with New Analysis." />}</div></div></> }
function Stat({ label, value }) { return <div className="stat"><small>{label}</small><strong>{value}</strong><span>workspace metric</span></div> }
function Risk({ level, score }) { return <span className={`risk ${String(level).toLowerCase()}`}>{level} · {Math.round(score * 100)}%</span> }
function Loading() { return <div className="loading">Loading secure workspace…</div> }
function Empty({ text }) { return <div className="empty"><FileText size={25} /><p>{text}</p></div> }

function Analyzer() {
  const [text, setText] = useState('');
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [sanitized, setSanitized] = useState(null);
  const [mode, setMode] = useState('adaptive');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const analyze = async () => {
    setBusy(true);
    setError('');
    try {
      const r = file ? await api.analyzeFile(file) : await api.analyzeText({ text, title: 'Workspace analysis' });
      setResult(r);
      setSanitized(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const sanitize = async () => {
    if (!result) return;
    setBusy(true);
    try {
      setSanitized(await api.sanitize(result.id, mode));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="analyzer">
      <div className="panel input-panel">
        <div className="panel-title">
          <div>
            <h3>Analyze sensitive content</h3>
            <p>Paste text or upload a TXT, PDF, or DOCX file.</p>
          </div>
          <span className="secure-badge"><Activity size={15} />Hybrid pipeline</span>
        </div>
        <textarea
          value={text}
          onChange={e => { setText(e.target.value); setFile(null) }}
          placeholder="Example: Contact Priya at priya@example.com or +91 9876543210…"
        />
        <div className="input-actions">
          <label className="file-btn">
            Choose file
            <input type="file" accept=".txt,.pdf,.docx" onChange={e => { setFile(e.target.files?.[0] || null); setText('') }} />
          </label>
          {file && <span className="file-name">{file.name}</span>}
          <button className="primary" disabled={busy || (!text.trim() && !file)} onClick={analyze}>
            {busy ? 'Analyzing…' : 'Analyze privacy risk'}
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {result && (
        <>
          <div className="result-grid">
            <div className="panel risk-card">
              <span className="tag">OVERALL PRIVACY RISK</span>
              <div className="risk-number">
                {Math.round(result.risk.score * 100)}<small>/100</small>
              </div>
              <Risk level={result.risk.level} score={result.risk.score} />
              <div className="explanations">
                {result.risk.explanations.map((x, i) => <p key={i}>• {x}</p>)}
              </div>
            </div>

            <div className="panel">
              <div className="panel-title">
                <div>
                  <h3>Detected entities</h3>
                  <p>{result.entities.length} findings across the input</p>
                </div>
              </div>
              <div className="entity-table">
                {result.entities.map((e, i) => (
                  <div className="entity-row" key={i}>
                    <div>
                      <b>{e.entity_type}</b>
                      <small>{e.source}</small>
                    </div>
                    <span>{e.text}</span>
                    <strong>{Math.round(e.confidence * 100)}%</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">
              <div>
                <h3>Adaptive de-identification</h3>
                <p>Transform the detected entities, then re-scan the output for residual leakage.</p>
              </div>
              <div className="sanitize-controls">
                <select value={mode} onChange={e => setMode(e.target.value)}>
                  <option value="adaptive">Adaptive policy</option>
                  <option value="pseudonymize">Pseudonymize</option>
                  <option value="mask">Mask</option>
                  <option value="remove">Remove</option>
                  <option value="hash">Hash</option>
                </select>
                <button className="primary" disabled={busy} onClick={sanitize}>
                  {busy ? 'Processing…' : 'Sanitize & audit'}
                </button>
              </div>
            </div>

            {sanitized && (
              <div className="sanitize-result">
                <div>
                  <span className="tag">SANITIZED OUTPUT</span>
                  <pre>{sanitized.sanitized_text}</pre>
                </div>
                <div className="before-after">
                  <div>
                    <small>Before</small>
                    <b>{Math.round(result.risk.score * 100)}%</b>
                  </div>
                  <div className="arrow">→</div>
                  <div>
                    <small>After</small>
                    <b>{Math.round(sanitized.post_risk.score * 100)}%</b>
                  </div>
                  <div>
                    <small>Risk reduction</small>
                    <b>{Math.round(sanitized.risk_reduction * 100)} pts</b>
                  </div>
                </div>
                {sanitized.remaining_entities.length > 0 && (
                  <div className="warning">
                    Output audit found {sanitized.remaining_entities.length} residual entity/ies. Review before external sharing.
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function HistoryPage() {
  const [rows, setRows] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');

  useEffect(() => {
    api.scans()
      .then(setRows)
      .catch((err) => setError(err.message));
  }, []);

  const openScan = async (id) => {
    setLoading(true);
    setError('');

    try {
      const data = await api.scan(id);
      setSelectedScan(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async () => {
    if (!selectedScan) return;

    try {
      await api.downloadReport(
        selectedScan.id,
        `privacyguard-scan-${selectedScan.id}.pdf`
      );
    } catch (err) {
      setError(err.message);
    }
  };

  const downloadSanitizedText = () => {
    if (!selectedScan?.sanitized_text) return;

    const blob = new Blob(
      [selectedScan.sanitized_text],
      { type: 'text/plain;charset=utf-8' }
    );

    const url = window.URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `privacyguard-sanitized-${selectedScan.id}.txt`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.URL.revokeObjectURL(url);
  };

  const filteredRows = rows
  .filter((scan) => {
    const query = search.toLowerCase().trim();

    if (!query) return true;

    return (
      String(scan.title || '')
        .toLowerCase()
        .includes(query) ||
      String(scan.source_type || '')
        .toLowerCase()
        .includes(query) ||
      String(scan.risk_level || '')
        .toLowerCase()
        .includes(query)
    );
  })
  .filter((scan) => {
    if (riskFilter === 'all') return true;

    return String(scan.risk_level || '').toLowerCase() === riskFilter;
  })
  .sort((a, b) => {
    if (sortBy === 'oldest') {
      return new Date(a.created_at) - new Date(b.created_at);
    }

    if (sortBy === 'highest') {
      return (b.risk_score || 0) - (a.risk_score || 0);
    }

    if (sortBy === 'lowest') {
      return (a.risk_score || 0) - (b.risk_score || 0);
    }

    return new Date(b.created_at) - new Date(a.created_at);
  });

  /* ------------------------------
     FULL SCAN DETAILS
  ------------------------------ */

  if (selectedScan) {
    return (
      <div className="panel">

        <div className="panel-title">
          <div>
            <button
              className="secondary-btn"
              onClick={() => setSelectedScan(null)}
            >
              ← Back to History
            </button>

            <h3 style={{ marginTop: '18px' }}>
              {selectedScan.title || 'Scan Details'}
            </h3>

            <p>
              Complete privacy analysis and detected PII information.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className="secondary-btn"
              onClick={downloadReport}
            >
              Download PDF
            </button>

            {selectedScan.sanitized_text && (
              <button
                className="primary"
                onClick={downloadSanitizedText}
              >
                Download Sanitized Text
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="error">
            {error}
          </div>
        )}

        {/* Risk Summary */}

        <div
          className="stats"
          style={{ marginTop: '20px' }}
        >
          <Stat
            label="Risk Score"
            value={
              selectedScan.risk_score != null
                ? `${Math.round(selectedScan.risk_score * 100)}%`
                : '—'
            }
          />

          <Stat
            label="Risk Level"
            value={selectedScan.risk_level || '—'}
          />

          <Stat
            label="Entities"
            value={selectedScan.entities?.length || 0}
          />

          <Stat
            label="Source"
            value={
              selectedScan.source_type
                ? selectedScan.source_type.toUpperCase()
                : '—'
            }
          />
        </div>

        {/* Original Input */}

        <div className="panel" style={{ marginTop: '20px' }}>
          <div className="panel-title">
            <div>
              <h3>Original Input</h3>
              <p>
                The content that was submitted for privacy analysis.
              </p>
            </div>
          </div>

          <pre className="analysis-text">
            {selectedScan.original_text ||
              'No original text available.'}
          </pre>
        </div>

        {/* Detected Entities */}

        <div className="panel" style={{ marginTop: '20px' }}>
          <div className="panel-title">
            <div>
              <h3>Detected PII Entities</h3>
              <p>
                Sensitive information identified by the hybrid detection pipeline.
              </p>
            </div>
          </div>

          {selectedScan.entities?.length ? (
            <div className="history-table">

              <div className="table-head">
                <span>Entity</span>
                <span>Type</span>
                <span>Confidence</span>
                <span>Source</span>
              </div>

              {selectedScan.entities.map((entity, index) => (
                <div
                  className="table-row"
                  key={`${entity.start}-${entity.end}-${index}`}
                >
                  <b>{entity.text}</b>

                  <span>
                    {entity.entity_type}
                  </span>

                  <span>
                    {entity.confidence != null
                      ? `${(entity.confidence * 100).toFixed(1)}%`
                      : '—'}
                  </span>

                  <span>
                    {entity.source || '—'}
                  </span>
                </div>
              ))}

            </div>
          ) : (
            <Empty text="No PII entities detected." />
          )}
        </div>

        {/* Sanitized Output */}

        <div className="panel" style={{ marginTop: '20px' }}>
          <div className="panel-title">
            <div>
              <h3>Sanitized Output</h3>
              <p>
                Privacy-preserving version generated by the sanitization process.
              </p>
            </div>

            {selectedScan.sanitized_text && (
              <button
                className="secondary-btn"
                onClick={downloadSanitizedText}
              >
                Download TXT
              </button>
            )}
          </div>

          {selectedScan.sanitized_text ? (
            <pre className="analysis-text">
              {selectedScan.sanitized_text}
            </pre>
          ) : (
            <Empty text="This scan has not been sanitized yet." />
          )}
        </div>

      </div>
    );
  }

  /* ------------------------------
     HISTORY LIST
  ------------------------------ */

  return (
    <div className="panel">

      <div className="panel-title">
        <div>
          <h3>Scan History</h3>
          <p>
            Open any previous analysis to inspect the complete result.
          </p>
        </div>
      </div>

  <div
  style={{
    display: 'grid',
    gridTemplateColumns: '1fr 180px 180px',
    gap: '12px',
    marginTop: '20px',
    marginBottom: '20px'
  }}
>
  <input
    type="text"
    placeholder="Search scans..."
    value={search}
    onChange={(e) => setSearch(e.target.value)}
  />

  <select
    value={riskFilter}
    onChange={(e) => setRiskFilter(e.target.value)}
  >
    <option value="all">All Risk Levels</option>
    <option value="low">Low</option>
    <option value="medium">Medium</option>
    <option value="high">High</option>
    <option value="critical">Critical</option>
  </select>

  <select
    value={sortBy}
    onChange={(e) => setSortBy(e.target.value)}
  >
    <option value="newest">Newest First</option>
    <option value="oldest">Oldest First</option>
    <option value="highest">Highest Risk</option>
    <option value="lowest">Lowest Risk</option>
  </select>
  </div>

      {error && (
        <div className="error">
          {error}
        </div>
      )}

      {loading && <Loading />}

      {filteredRows.length ? (
        <div className="history-table">

          <div className="table-head">
            <span>Document</span>
            <span>Source</span>
            <span>Entities</span>
            <span>Risk</span>
            <span>Date</span>
            <span>Action</span>
          </div>

          {filteredRows.map((s) => (
            <div className="table-row" key={s.id}>

              <b>{s.title}</b>

              <span>
                {s.source_type?.toUpperCase()}
              </span>

              <span>
                {s.entity_count}
              </span>

              <Risk
                level={s.risk_level}
                score={s.risk_score}
              />

              <span>
                {new Date(s.created_at).toLocaleString()}
              </span>

              <button
                className="secondary-btn"
                onClick={() => openScan(s.id)}
              >
                View Analysis
              </button>

            </div>
          ))}

        </div>
      ) : (
        !loading && (
          <Empty text="No scan history yet." />
        )
      )}

    </div>
  );
}
function AuditPage() { const [rows, setRows] = useState([]); useEffect(() => { api.audit().then(setRows) }, []); return <div className="panel"><div className="panel-title"><div><h3>Audit trail</h3><p>Track analysis and sanitization actions in your workspace.</p></div><span className="secure-badge"><LockKeyhole size={15} />Audit logging</span></div>{rows.length ? <div className="history-table"><div className="table-head"><span>Action</span><span>Scan</span><span>Details</span><span>Time</span></div>{rows.map(r => <div className="table-row" key={r.id}><b>{r.action}</b><span>#{r.scan_id || '—'}</span><code>{JSON.stringify(r.details)}</code><span>{new Date(r.created_at).toLocaleString()}</span></div>)}</div> : <Empty text="No audit events yet." />}</div> }

createRoot(document.getElementById('root')).render(<App />);
