import { useState, useEffect } from 'react';
import { getAttackPath } from '../api';

const TACTICS = [
  { id:'TA0001', name:'Initial\nAccess' },
  { id:'TA0002', name:'Execution' },
  { id:'TA0003', name:'Persistence' },
  { id:'TA0004', name:'Privilege\nEscalation' },
  { id:'TA0005', name:'Defense\nEvasion' },
  { id:'TA0006', name:'Credential\nAccess' },
  { id:'TA0007', name:'Discovery' },
  { id:'TA0008', name:'Lateral\nMovement' },
  { id:'TA0009', name:'Collection' },
  { id:'TA0010', name:'Exfiltration' },
  { id:'TA0040', name:'Impact' },
];

export default function MitreHeatmap() {
  const [data,    setData]    = useState(null);
  const [hovered, setHovered] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAttackPath()
      .then(r => setData(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ padding:40, textAlign:'center',
      fontFamily:'var(--font-mono)', color:'var(--text-dim)' }}>
      Loading ATT&CK data...
    </div>
  );

  const activeSteps  = data?.steps || [];
  const activeTacticIds = new Set(activeSteps.map(s => s.tactic_id));
  const techByTactic = {};
  activeSteps.forEach(step => {
    techByTactic[step.tactic_id] = step.techniques || [];
  });

  return (
    <div style={{ maxWidth:1200 }}>
      <div style={{ background:'var(--panel)', border:'1px solid var(--border)',
        borderRadius:8, padding:'24px' }}>

        <div style={{ display:'flex', justifyContent:'space-between',
          alignItems:'center', marginBottom:20 }}>
          <div>
            <h2 style={{ fontFamily:'var(--font-mono)', fontSize:16,
              fontWeight:700, color:'var(--cyan)', marginBottom:4 }}>
              ATT&CK Threat Coverage
            </h2>
            <p style={{ fontSize:12, color:'var(--text-sec)' }}>
              {data?.total_tactics || 0} active tactic{data?.total_tactics !== 1 ? 's' : ''} · Furthest reach:{' '}
              <span style={{ color:'var(--purple)', fontWeight:600 }}>
                {data?.highest_impact || 'None'}
              </span>
            </p>
          </div>
          <div style={{ display:'flex', gap:12 }}>
            {[['Active','var(--purple)'],['Inactive','var(--border)']].map(([l,c]) => (
              <div key={l} style={{ display:'flex', alignItems:'center', gap:5 }}>
                <div style={{ width:10, height:10, borderRadius:2, background:c }}/>
                <span style={{ fontSize:10, color:'var(--text-dim)' }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display:'flex', gap:3, overflowX:'auto' }}>
          {TACTICS.map(tactic => {
            const isActive = activeTacticIds.has(tactic.id);
            const techs    = techByTactic[tactic.id] || [];
            return (
              <div key={tactic.id} style={{ flex:1, minWidth:70 }}>
                <div style={{
                  background: isActive ? 'rgba(139,92,246,0.15)' : 'var(--surface)',
                  border:`1px solid ${isActive ? 'rgba(139,92,246,0.5)' : 'var(--border)'}`,
                  borderRadius:'4px 4px 0 0', padding:'8px 4px',
                  textAlign:'center', marginBottom:3,
                  boxShadow: isActive ? '0 0 12px rgba(139,92,246,0.2)' : 'none',
                }}>
                  <div style={{
                    fontFamily:'var(--font-sans)', fontSize:9, fontWeight:700,
                    color: isActive ? 'var(--purple)' : 'var(--text-dim)',
                    whiteSpace:'pre-line', lineHeight:1.3,
                  }}>{tactic.name}</div>
                  {isActive && (
                    <div style={{ fontFamily:'var(--font-mono)', fontSize:11,
                      color:'var(--purple)', fontWeight:700, marginTop:2 }}>
                      {techs.length}
                    </div>
                  )}
                </div>

                <div style={{ display:'flex', flexDirection:'column', gap:2 }}>
                  {techs.length > 0 ? techs.map(tech => {
                    const isHov = hovered === tech.technique_id;
                    return (
                      <div key={tech.technique_id}
                        onMouseEnter={() => setHovered(tech.technique_id)}
                        onMouseLeave={() => setHovered(null)}
                        style={{
                          background:'rgba(139,92,246,0.2)',
                          border:'1px solid rgba(139,92,246,0.5)',
                          borderRadius:3, padding:'6px 4px', cursor:'pointer',
                          position:'relative', transition:'all 0.15s',
                          boxShadow: isHov ? '0 0 10px rgba(139,92,246,0.5)' : 'none',
                          transform: isHov ? 'scale(1.04)' : 'scale(1)',
                        }}>
                        <div style={{ fontFamily:'var(--font-mono)', fontSize:8,
                          color:'var(--purple)', fontWeight:700, textAlign:'center' }}>
                          {tech.technique_id}
                        </div>
                        {isHov && (
                          <div style={{
                            position:'absolute', zIndex:99, bottom:'110%', left:'50%',
                            transform:'translateX(-50%)',
                            background:'var(--panel)', border:'1px solid rgba(139,92,246,0.5)',
                            borderRadius:6, padding:'8px 10px', width:180,
                            boxShadow:'0 4px 20px rgba(139,92,246,0.3)',
                            pointerEvents:'none',
                          }}>
                            <div style={{ fontFamily:'var(--font-mono)', fontSize:11,
                              color:'var(--purple)', fontWeight:700 }}>{tech.technique_id}</div>
                            <div style={{ fontSize:11, color:'var(--text)', marginTop:3 }}>
                              {tech.technique_name}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  }) : (
                    <div style={{ background:'var(--surface)',
                      border:'1px solid var(--border)',
                      borderRadius:3, padding:'6px 4px' }}>
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:8,
                        color:'var(--text-dim)', textAlign:'center' }}>—</div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {data?.narrative && (
          <div style={{ marginTop:20, padding:'14px 16px',
            background:'rgba(139,92,246,0.08)',
            border:'1px solid rgba(139,92,246,0.3)',
            borderRadius:8, fontSize:12, color:'var(--text-sec)', lineHeight:1.6 }}>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:10,
              color:'var(--purple)', fontWeight:700, marginRight:8 }}>
              ADVERSARY NARRATIVE
            </span>
            {data.narrative}
          </div>
        )}
      </div>

      {activeSteps.length > 0 && (
        <div style={{ marginTop:16, background:'var(--panel)',
          border:'1px solid var(--border)', borderRadius:8, padding:'20px 24px' }}>
          <div style={{ fontSize:12, fontWeight:600, color:'var(--text-sec)',
            textTransform:'uppercase', letterSpacing:1, marginBottom:14 }}>
            Active Techniques
          </div>
          <div style={{ display:'flex', flexWrap:'wrap', gap:10 }}>
            {activeSteps.flatMap(s => s.techniques).map((tech, i) => (
              <div key={i} style={{ background:'rgba(139,92,246,0.12)',
                border:'1px solid rgba(139,92,246,0.4)',
                borderRadius:7, padding:'10px 14px', minWidth:160 }}>
                <div style={{ fontFamily:'var(--font-mono)', fontSize:12,
                  color:'var(--purple)', fontWeight:700 }}>{tech.technique_id}</div>
                <div style={{ fontSize:12, color:'var(--text)', marginTop:3 }}>
                  {tech.technique_name}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
