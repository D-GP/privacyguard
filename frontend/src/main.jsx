import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import {ShieldCheck,LayoutDashboard,ScanSearch,History,FileText,LogOut,Menu,X,Activity,LockKeyhole} from 'lucide-react';
import {api} from './services/api';
import './styles/app.css';

function Auth({onAuth}){
 const [mode,setMode]=useState('login'); const [form,setForm]=useState({name:'',email:'',password:''}); const [error,setError]=useState('');
 const submit=async e=>{e.preventDefault();setError('');try{const r=mode==='login'?await api.login(form):await api.register(form);localStorage.setItem('pg_token',r.token);onAuth(r.user)}catch(x){setError(x.message)}};
 return <div className="auth-shell"><div className="auth-art"><div className="brand"><ShieldCheck size={28}/> PrivacyGuard AI</div><h1>Privacy by design.<br/><span>Intelligence with control.</span></h1><p>Detect sensitive information, understand re-identification risk, and transform data safely before it reaches downstream systems.</p><div className="security-pills"><span>Hybrid PII detection</span><span>Risk-aware anonymization</span><span>Audit-ready</span></div></div><div className="auth-card"><div className="auth-head"><div className="logo-mini"><ShieldCheck size={22}/></div><h2>{mode==='login'?'Welcome back':'Create your workspace'}</h2><p>{mode==='login'?'Sign in to your privacy workspace.':'Start building safer data workflows.'}</p></div>{error&&<div className="error">{error}</div>}<form onSubmit={submit}>{mode==='register'&&<label>Full name<input value={form.name} onChange={e=>setForm({...form,name:e.target.value})} required/></label>}<label>Email<input type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})} required/></label><label>Password<input type="password" minLength="8" value={form.password} onChange={e=>setForm({...form,password:e.target.value})} required/></label><button className="primary full">{mode==='login'?'Sign in':'Create account'}</button></form><button className="link-btn" onClick={()=>{setMode(mode==='login'?'register':'login');setError('')}}>{mode==='login'?"Don't have an account? Create one":"Already have an account? Sign in"}</button></div></div>
}

function App(){
 const [user,setUser]=useState(null); const [page,setPage]=useState('dashboard'); const [mobile,setMobile]=useState(false);
 useEffect(()=>{if(localStorage.getItem('pg_token')) api.me().then(setUser).catch(()=>localStorage.removeItem('pg_token'))},[]);
 if(!user) return <Auth onAuth={setUser}/>;
 const logout=()=>{localStorage.removeItem('pg_token');setUser(null)};
 const nav=[['dashboard','Dashboard',LayoutDashboard],['analyze','New Analysis',ScanSearch],['history','Scan History',History],['audit','Audit Trail',LockKeyhole]];
 return <div className="app"><aside className={mobile?'sidebar open':'sidebar'}><div className="sidebar-brand"><ShieldCheck size={27}/><span>PrivacyGuard <b>AI</b></span><button className="icon mobile-close" onClick={()=>setMobile(false)}><X/></button></div><nav>{nav.map(([id,label,Icon])=><button key={id} className={page===id?'nav-item active':'nav-item'} onClick={()=>{setPage(id);setMobile(false)}}><Icon size={18}/>{label}</button>)}</nav><div className="sidebar-bottom"><div className="user-mini"><div className="avatar">{user.name[0]}</div><div><b>{user.name}</b><small>{user.role}</small></div></div><button className="nav-item" onClick={logout}><LogOut size={18}/>Sign out</button></div></aside><main className="main"><header className="topbar"><button className="icon mobile-menu" onClick={()=>setMobile(true)}><Menu/></button><div><span className="eyebrow">SECURE DATA WORKSPACE</span><h1>{nav.find(x=>x[0]===page)?.[1]}</h1></div><div className="top-status"><span className="status-dot"></span>Local analysis ready</div></header><section className="content">{page==='dashboard'&&<Dashboard/>}{page==='analyze'&&<Analyzer/>}{page==='history'&&<HistoryPage/>}{page==='audit'&&<AuditPage/>}</section></main></div>
}

function Dashboard(){const [d,setD]=useState(null);const [scans,setScans]=useState([]);useEffect(()=>{Promise.all([api.dashboard(),api.scans()]).then(([a,b])=>{setD(a);setScans(b.slice(0,5))})},[]);if(!d)return <Loading/>;return <><div className="hero"><div><span className="tag">PRIVACY INTELLIGENCE</span><h2>Understand your data before it leaves your control.</h2><p>PrivacyGuard combines deterministic patterns, NLP detection, contextual analysis and risk-aware de-identification.</p></div><div className="hero-icon"><ShieldCheck size={48}/></div></div><div className="stats"><Stat label="Total scans" value={d.total_scans}/><Stat label="High-risk scans" value={d.high_risk_scans}/><Stat label="Average risk" value={`${d.average_risk}%`}/><Stat label="Entities found" value={d.entities_found}/></div><div className="grid-2"><div className="panel"><div className="panel-title"><div><h3>Risk distribution</h3><p>Across your recent workspace scans</p></div></div><div className="bars">{Object.entries(d.risk_distribution).map(([k,v])=><div className="bar-row" key={k}><span>{k}</span><div className="bar"><i style={{width:`${Math.min(100,v*20)}%`}}></i></div><b>{v}</b></div>)}</div></div><div className="panel"><div className="panel-title"><div><h3>Recent scans</h3><p>Latest privacy assessments</p></div></div>{scans.length?<div className="scan-list">{scans.map(s=><div className="scan-row" key={s.id}><div><b>{s.title}</b><small>{new Date(s.created_at).toLocaleString()}</small></div><Risk level={s.risk_level} score={s.risk_score}/></div>)}</div>:<Empty text="No scans yet. Start with New Analysis."/>}</div></div></>}
function Stat({label,value}){return <div className="stat"><small>{label}</small><strong>{value}</strong><span>workspace metric</span></div>}
function Risk({level,score}){return <span className={`risk ${String(level).toLowerCase()}`}>{level} · {Math.round(score*100)}%</span>}
function Loading(){return <div className="loading">Loading secure workspace…</div>}
function Empty({text}){return <div className="empty"><FileText size={25}/><p>{text}</p></div>}

function Analyzer(){
  const [text,setText]=useState('');
  const [file,setFile]=useState(null);
  const [result,setResult]=useState(null);
  const [sanitized,setSanitized]=useState(null);
  const [mode,setMode]=useState('adaptive');
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');

  const analyze=async()=>{
    setBusy(true);
    setError('');
    try{
      const r=file?await api.analyzeFile(file):await api.analyzeText({text,title:'Workspace analysis'});
      setResult(r);
      setSanitized(null);
    }catch(e){
      setError(e.message);
    }finally{
      setBusy(false);
    }
  };

  const sanitize=async()=>{
    if(!result) return;
    setBusy(true);
    try{
      setSanitized(await api.sanitize(result.id,mode));
    }catch(e){
      setError(e.message);
    }finally{
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
          <span className="secure-badge"><Activity size={15}/>Hybrid pipeline</span>
        </div>
        <textarea
          value={text}
          onChange={e=>{setText(e.target.value);setFile(null)}}
          placeholder="Example: Contact Priya at priya@example.com or +91 9876543210…"
        />
        <div className="input-actions">
          <label className="file-btn">
            Choose file
            <input type="file" accept=".txt,.pdf,.docx" onChange={e=>{setFile(e.target.files?.[0]||null);setText('')}}/>
          </label>
          {file&&<span className="file-name">{file.name}</span>}
          <button className="primary" disabled={busy||(!text.trim()&&!file)} onClick={analyze}>
            {busy?'Analyzing…':'Analyze privacy risk'}
          </button>
        </div>
        {error&&<div className="error">{error}</div>}
      </div>

      {result && (
        <>
          <div className="result-grid">
            <div className="panel risk-card">
              <span className="tag">OVERALL PRIVACY RISK</span>
              <div className="risk-number">
                {Math.round(result.risk.score*100)}<small>/100</small>
              </div>
              <Risk level={result.risk.level} score={result.risk.score}/>
              <div className="explanations">
                {result.risk.explanations.map((x,i)=><p key={i}>• {x}</p>)}
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
                {result.entities.map((e,i)=>(
                  <div className="entity-row" key={i}>
                    <div>
                      <b>{e.entity_type}</b>
                      <small>{e.source}</small>
                    </div>
                    <span>{e.text}</span>
                    <strong>{Math.round(e.confidence*100)}%</strong>
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
                <select value={mode} onChange={e=>setMode(e.target.value)}>
                  <option value="adaptive">Adaptive policy</option>
                  <option value="pseudonymize">Pseudonymize</option>
                  <option value="mask">Mask</option>
                  <option value="remove">Remove</option>
                  <option value="hash">Hash</option>
                </select>
                <button className="primary" disabled={busy} onClick={sanitize}>
                  {busy?'Processing…':'Sanitize & audit'}
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
                    <b>{Math.round(result.risk.score*100)}%</b>
                  </div>
                  <div className="arrow">→</div>
                  <div>
                    <small>After</small>
                    <b>{Math.round(sanitized.post_risk.score*100)}%</b>
                  </div>
                  <div>
                    <small>Risk reduction</small>
                    <b>{Math.round(sanitized.risk_reduction*100)} pts</b>
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

function HistoryPage(){const [rows,setRows]=useState([]);useEffect(()=>{api.scans().then(setRows)},[]);return <div className="panel"><div className="panel-title"><div><h3>Scan history</h3><p>Your latest privacy assessments and their risk outcomes.</p></div></div>{rows.length?<div className="history-table"><div className="table-head"><span>Document</span><span>Source</span><span>Entities</span><span>Risk</span><span>Date</span></div>{rows.map(s=><div className="table-row" key={s.id}><b>{s.title}</b><span>{s.source_type.toUpperCase()}</span><span>{s.entity_count}</span><Risk level={s.risk_level} score={s.risk_score}/><span>{new Date(s.created_at).toLocaleString()}</span></div>)}</div>:<Empty text="No scan history yet."/>}</div>}
function AuditPage(){const [rows,setRows]=useState([]);useEffect(()=>{api.audit().then(setRows)},[]);return <div className="panel"><div className="panel-title"><div><h3>Audit trail</h3><p>Track analysis and sanitization actions in your workspace.</p></div><span className="secure-badge"><LockKeyhole size={15}/>Audit logging</span></div>{rows.length?<div className="history-table"><div className="table-head"><span>Action</span><span>Scan</span><span>Details</span><span>Time</span></div>{rows.map(r=><div className="table-row" key={r.id}><b>{r.action}</b><span>#{r.scan_id||'—'}</span><code>{JSON.stringify(r.details)}</code><span>{new Date(r.created_at).toLocaleString()}</span></div>)}</div>:<Empty text="No audit events yet."/>}</div>}

createRoot(document.getElementById('root')).render(<App/>);
