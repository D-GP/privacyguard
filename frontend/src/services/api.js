const API = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

async function request(path, options = {}) {
  const headers = options.body instanceof FormData ? {} : {'Content-Type':'application/json'};
  const token = localStorage.getItem('pg_token');
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, {...options, headers:{...headers,...(options.headers||{})}});
  const data = await res.json().catch(()=>({message:'Unexpected server response'}));
  if (!res.ok) throw new Error(data.message || 'Request failed');
  return data;
}
export const api = {
  login: (payload)=>request('/auth/login',{method:'POST',body:JSON.stringify(payload)}),
  register: (payload)=>request('/auth/register',{method:'POST',body:JSON.stringify(payload)}),
  me: ()=>request('/auth/me'),
  dashboard: ()=>request('/dashboard'),
  scans: ()=>request('/scans'),
  scan: (id)=>request(`/scans/${id}`),
  analyzeText: (payload)=>request('/analyze',{method:'POST',body:JSON.stringify(payload)}),
  analyzeFile: (file)=>{const fd=new FormData();fd.append('file',file);return request('/analyze',{method:'POST',body:fd});},
  sanitize: (id,mode)=>request(`/scans/${id}/sanitize`,{method:'POST',body:JSON.stringify({mode})}),
  audit: ()=>request('/audit')
};
