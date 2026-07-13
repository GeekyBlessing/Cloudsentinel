import { useState, useEffect } from 'react';
import { getCompliance } from '../api';

const FW_META = {
  CIS:      { name:'CIS AWS Foundations Benchmark v1.5', color:'var(--cyan)' },
  NIST_CSF: { name:'NIST Cybersecurity Framework',       color:'var(--purple)' },
  SOC2:     { name:'SOC 2 Type II',                      color:'var(--amber)' },
  PCI_DSS:  { name:'PCI DSS v4.0',                       color:'var(--green)' },
};

export default function Compliance() {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getCompliance()
      .then(r => setData(r.data.frameworks || r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ padding:40, textAlign:'center',
      fontFamily:'var(--font-mono)', color:'var(--text-dim)' }}>
      Loading compliance data...
    </div>
  );

  return (
    <div style={{ maxWidth:900, display:'flex', flexDirection:'column', gap:16 }}>
      {Object.entries(data || {}).map(([fw, d]) => {
        const meta   = FW_META[fw] || { name:fw, color:'var(--cyan)' };
        const pct    = d.pass_pct || 0;
        const color  = pct >= 90 ? 'var(--green)' : pct >= 75 ? 'var(--amber)' : 'var(--crimson)';
        const status = pct >= 90 ? 'COMPLIANT' : pct >= 75 ? 'PARTIAL' : 'NON-COMPLIANT';

        return (
          <div key={fw} style={{
            background:'var(--panel)', border:'1px solid var(--border)',
            borderRadius:8, overflow:'hidden',
            borderTop:`3px solid ${meta.color}`,
          }}>
            <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)' }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
                <div>
                  <div style={{ fontSize:14, fontWeight:700,
                    color:'var(--text)', marginBottom:4 }}>{meta.name}</div>
                  <div style={{ display:'flex', gap:12, alignItems:'center' }}>
                    <span style={{
                      fontFamily:'var(--font-mono)', fontSize:10, fontWeight:700,
                      color, background:`${color}22`, padding:'2px 8px', borderRadius:3,
                    }}>{status}</span>
                    <span style={{ fontSize:12, color:'var(--text-dim)' }}>
                      {d.passing}/{d.total} controls passing
                    </span>
                  </div>
                </div>
                <div style={{ textAlign:'right' }}>
                  <div style={{ fontFamily:'var(--font-mono)', fontSize:32,
                    fontWeight:700, color }}>{pct}%</div>
                </div>
              </div>
              <div style={{ marginTop:14, background:'var(--surface)',
                borderRadius:4, height:8, overflow:'hidden' }}>
                <div style={{
                  width:`${pct}%`, height:'100%', background:meta.color,
                  borderRadius:4, transition:'width 1s ease',
                }}/>
              </div>
            </div>

            {d.failing_controls?.length > 0 && (
              <div style={{ padding:'14px 20px' }}>
                <div style={{ fontSize:11, color:'var(--text-dim)',
                  marginBottom:10, textTransform:'uppercase', letterSpacing:1 }}>
                  Failing Controls ({d.failing})
                </div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:8 }}>
                  {d.failing_controls.map(ctrl => (
                    <span key={ctrl} style={{
                      fontFamily:'var(--font-mono)', fontSize:11,
                      color:'var(--crimson)',
                      background:'rgba(239,68,68,0.12)',
                      border:'1px solid rgba(239,68,68,0.3)',
                      padding:'3px 10px', borderRadius:4,
                    }}>{ctrl}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
