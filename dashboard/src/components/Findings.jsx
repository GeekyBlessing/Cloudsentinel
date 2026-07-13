import { useState, useEffect } from 'react';
import { getFindings, updateStatus } from '../api';

const SEV_COLOR = { CRITICAL:'#EF4444', HIGH:'#F59E0B', MEDIUM:'#F97316', LOW:'#10B981', INFO:'#94A3B8' };
const SEV_BG    = { CRITICAL:'rgba(239,68,68,0.15)', HIGH:'rgba(245,158,11,0.15)',
                    MEDIUM:'rgba(249,115,22,0.15)', LOW:'rgba(16,185,129,0.15)', INFO:'rgba(148,163,184,0.12)' };

function Section({ label, children }) {
  return (
    <div style={{ marginBottom:20 }}>
      <div style={{
        fontFamily:'var(--font-mono)', fontSize:10, fontWeight:700,
        color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:1.2,
        borderBottom:'1px solid var(--border)', paddingBottom:6, marginBottom:8,
      }}>{label}</div>
      {children}
    </div>
  );
}

function KV({ label, value }) {
  return (
    <div style={{ display:'flex', gap:8, marginBottom:5 }}>
      <span style={{ fontSize:11, color:'var(--text-dim)', width:65, flexShrink:0 }}>{label}</span>
      <span style={{ fontFamily:'var(--font-mono)', fontSize:11,
        color:'var(--text)', wordBreak:'break-all' }}>{value}</span>
    </div>
  );
}

function FindingDrawer({ finding, onClose, onStatusChange }) {
  if (!finding) return null;
  const sev = finding.severity;
  const mitre = finding.mitre || [];
  const rem = finding.remediation;
  return (
    <>
      <div onClick={onClose} style={{
        position:'fixed', inset:0, background:'rgba(0,0,0,0.5)', zIndex:199
      }}/>
      <div style={{
        position:'fixed', top:0, right:0, bottom:0, width:460,
        background:'var(--surface)', borderLeft:'1px solid var(--border)',
        boxShadow:'-8px 0 40px rgba(0,0,0,0.5)',
        overflowY:'auto', zIndex:200,
      }}>
        <div style={{ padding:'20px 24px', borderBottom:'1px solid var(--border)',
          position:'sticky', top:0, background:'var(--surface)' }}>
          <div style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:11,
              color:'var(--text-dim)' }}>{finding.id}</span>
            <button onClick={onClose} style={{
              background:'transparent', border:'none',
              color:'var(--text-sec)', cursor:'pointer', fontSize:18 }}>✕</button>
          </div>
          <h2 style={{ fontSize:15, fontWeight:700, color:'var(--text)', marginBottom:10 }}>
            {finding.title}
          </h2>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <span className="tag" style={{ color:SEV_COLOR[sev], background:SEV_BG[sev] }}>
              {sev}
            </span>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:11,
              color:SEV_COLOR[sev] }}>Risk: {finding.risk_score}/10</span>
          </div>
        </div>

        <div style={{ padding:'20px 24px' }}>
          <Section label="Resource">
            <KV label="ID"      value={finding.resource_id}/>
            <KV label="Service" value={finding.service}/>
            <KV label="Region"  value={finding.region}/>
            <KV label="Account" value={finding.account_id}/>
          </Section>

          {finding.blast_radius && (
            <Section label="Blast Radius">
              <div style={{ display:'flex', alignItems:'center', gap:10, margin:'6px 0' }}>
                <div style={{ flex:1, background:'var(--panel)', borderRadius:3, height:8 }}>
                  <div style={{
                    width:`${finding.blast_radius.score}%`, height:'100%',
                    background: finding.blast_radius.score >= 70 ? '#EF4444' : '#F59E0B',
                    borderRadius:3,
                  }}/>
                </div>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:12, fontWeight:700,
                  color: finding.blast_radius.score >= 70 ? '#EF4444' : '#F59E0B' }}>
                  {finding.blast_radius.score}/100
                </span>
              </div>
              <div style={{ display:'flex', gap:12, fontSize:10, color:'var(--text-dim)' }}>
                {finding.blast_radius.lateral_movement   && <span style={{color:'#F59E0B'}}>⚡ Lateral Movement</span>}
                {finding.blast_radius.data_exfil_risk    && <span style={{color:'#EF4444'}}>📤 Data Exfil</span>}
                {finding.blast_radius.privilege_esc_risk && <span style={{color:'#8B5CF6'}}>⬆ Privilege Esc</span>}
              </div>
            </Section>
          )}

          {mitre.length > 0 && (
            <Section label="MITRE ATT&CK">
              <div style={{ display:'flex', flexWrap:'wrap', gap:6, marginTop:6 }}>
                {mitre.map(m => (
                  <div key={m.technique_id} style={{
                    background:'rgba(139,92,246,0.15)',
                    border:'1px solid rgba(139,92,246,0.4)',
                    borderRadius:5, padding:'6px 10px',
                  }}>
                    <div style={{ fontFamily:'var(--font-mono)', fontSize:11,
                      color:'var(--purple)', fontWeight:700 }}>{m.technique_id}</div>
                    <div style={{ fontSize:11, color:'var(--text-sec)', marginTop:2 }}>
                      {m.technique_name}
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {finding.controls?.length > 0 && (
            <Section label="Compliance Controls">
              <div style={{ display:'flex', flexWrap:'wrap', gap:6, marginTop:6 }}>
                {finding.controls.map(c => (
                  <span key={c.control_id} style={{
                    fontFamily:'var(--font-mono)', fontSize:10,
                    color:'var(--cyan)', background:'var(--cyan-dim)',
                    border:'1px solid rgba(0,212,255,0.3)',
                    padding:'3px 8px', borderRadius:4,
                  }}>{c.framework}: {c.control_id}</span>
                ))}
              </div>
            </Section>
          )}

          {rem?.steps?.length > 0 && (
            <Section label="Remediation Steps">
              {rem.steps.map((s, i) => (
                <div key={i} style={{ display:'flex', gap:8, marginBottom:8,
                  fontSize:12, color:'var(--text-sec)', lineHeight:1.5 }}>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:10,
                    color:'var(--green)', fontWeight:700, marginTop:1 }}>{i+1}.</span>
                  <span>{s}</span>
                </div>
              ))}
            </Section>
          )}

          <div style={{ display:'flex', gap:10, marginTop:20 }}>
            <button onClick={() => onStatusChange(finding.id, 'REMEDIATED')} style={{
              flex:1, padding:'10px', cursor:'pointer',
              background:'rgba(16,185,129,0.15)', border:'1px solid var(--green)',
              borderRadius:6, color:'var(--green)', fontWeight:600, fontSize:13,
            }}>✓ Mark Remediated</button>
            <button onClick={() => onStatusChange(finding.id, 'SUPPRESSED', 'Accepted risk')} style={{
              flex:1, padding:'10px', cursor:'pointer',
              background:'rgba(245,158,11,0.15)', border:'1px solid var(--amber)',
              borderRadius:6, color:'var(--amber)', fontWeight:600, fontSize:13,
            }}>Suppress</button>
          </div>
        </div>
      </div>
    </>
  );
}

export default function Findings() {
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filters, setFilters]   = useState({ cloud:'ALL', severity:'ALL', status:'OPEN' });
  const [loading, setLoading]   = useState(true);

  useEffect(() => { load(); }, [filters]);

  async function load() {
    setLoading(true);
    try {
      const params = {};
      if (filters.cloud    !== 'ALL') params.cloud    = filters.cloud;
      if (filters.severity !== 'ALL') params.severity = filters.severity;
      if (filters.status   !== 'ALL') params.status   = filters.status;
      const { data } = await getFindings(params);
      setFindings(data.findings || []);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }

  async function handleStatus(id, status, reason) {
    try {
      await updateStatus(id, status, reason);
      setSelected(null);
      load();
    } catch (e) { console.error(e); }
  }

  const filterRow = (group) => {
    const opts = {
      cloud:    ['ALL','AWS','AZURE','GCP'],
      severity: ['ALL','CRITICAL','HIGH','MEDIUM','LOW'],
      status:   ['ALL','OPEN','REMEDIATED','SUPPRESSED'],
    }[group];
    return (
      <div style={{ display:'flex', gap:1 }}>
        {opts.map((o, i) => (
          <button key={o} onClick={() => setFilters(f => ({...f, [group]:o}))} style={{
            background: filters[group]===o ? 'var(--cyan-dim)' : 'var(--surface)',
            border:`1px solid ${filters[group]===o ? 'var(--cyan)' : 'var(--border)'}`,
            borderRadius: i===0?'5px 0 0 5px':i===opts.length-1?'0 5px 5px 0':'0',
            padding:'6px 12px', cursor:'pointer',
            color: filters[group]===o ? 'var(--cyan)' : 'var(--text-sec)',
            fontFamily:'var(--font-mono)', fontSize:11, transition:'all 0.15s',
          }}>{o}</button>
        ))}
      </div>
    );
  };

  return (
    <div style={{ maxWidth:1100 }}>
      <div style={{ display:'flex', gap:10, marginBottom:16, flexWrap:'wrap', alignItems:'center' }}>
        {filterRow('cloud')}
        {filterRow('severity')}
        {filterRow('status')}
        <span style={{ fontSize:12, color:'var(--text-dim)' }}>
          {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div style={{ background:'var(--panel)', border:'1px solid var(--border)', borderRadius:8 }}>
        <div style={{
          display:'grid', gridTemplateColumns:'80px 1fr 140px 60px',
          padding:'10px 16px', borderBottom:'1px solid var(--border)',
          fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-dim)',
          textTransform:'uppercase', letterSpacing:1,
        }}>
          <span>Severity</span><span>Finding</span><span>TTPs</span><span>Risk</span>
        </div>

        {loading ? (
          <div style={{ padding:32, textAlign:'center',
            fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-dim)' }}>
            Loading findings...
          </div>
        ) : findings.length === 0 ? (
          <div style={{ padding:32, textAlign:'center',
            fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-dim)' }}>
            No findings match the current filters.
          </div>
        ) : findings.map(f => (
          <div key={f.id} onClick={() => setSelected(f)} style={{
            display:'grid', gridTemplateColumns:'80px 1fr 140px 60px',
            padding:'12px 16px', borderBottom:'1px solid var(--border)',
            cursor:'pointer', transition:'background 0.12s',
            background: selected?.id===f.id ? 'rgba(0,212,255,0.06)' : 'transparent',
            borderLeft: selected?.id===f.id ? '3px solid var(--cyan)' : '3px solid transparent',
          }}
          onMouseEnter={e => { if(selected?.id!==f.id) e.currentTarget.style.background='var(--surface)'; }}
          onMouseLeave={e => { if(selected?.id!==f.id) e.currentTarget.style.background='transparent'; }}>
            <div>
              <span className="tag" style={{ color:SEV_COLOR[f.severity], background:SEV_BG[f.severity] }}>
                {f.severity}
              </span>
            </div>
            <div>
              <div style={{ fontSize:13, fontWeight:500, color:'var(--text)', marginBottom:3 }}>
                {f.title}
              </div>
              <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-dim)' }}>
                {f.resource_id}
              </div>
            </div>
            <div style={{ display:'flex', flexWrap:'wrap', gap:4, alignItems:'flex-start' }}>
              {(f.ttp_ids || []).slice(0,3).map(t => (
                <span key={t} style={{
                  fontFamily:'var(--font-mono)', fontSize:9,
                  color:'var(--purple)', background:'rgba(139,92,246,0.15)',
                  padding:'1px 5px', borderRadius:3,
                }}>{t}</span>
              ))}
            </div>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:12, fontWeight:700,
              color: f.risk_score>=8?'#EF4444':f.risk_score>=6?'#F59E0B':'#10B981' }}>
              {f.risk_score}
            </div>
          </div>
        ))}
      </div>

      <FindingDrawer
        finding={selected}
        onClose={() => setSelected(null)}
        onStatusChange={handleStatus}
      />
    </div>
  );
}
