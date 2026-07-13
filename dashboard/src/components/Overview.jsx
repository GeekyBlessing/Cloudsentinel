const SEV_COLOR = { CRITICAL:'#EF4444', HIGH:'#F59E0B', MEDIUM:'#F97316', LOW:'#10B981', INFO:'#94A3B8' };
const CLOUD_COLOR = { AWS:'#FF9900', AZURE:'#0078D4', GCP:'#4285F4' };

function StatCard({ label, value, color, sub, icon }) {
  return (
    <div style={{
      background:'var(--panel)', border:'1px solid var(--border)',
      borderTop:`2px solid ${color}`, borderRadius:8,
      padding:'16px 20px', flex:1, minWidth:140,
    }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
        <div>
          <div style={{ fontFamily:'var(--font-sans)', fontSize:11, color:'var(--text-sec)',
            textTransform:'uppercase', letterSpacing:1.2, marginBottom:6 }}>{label}</div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:28, fontWeight:700, color }}>
            {value ?? '--'}
          </div>
          {sub && <div style={{ fontSize:11, color:'var(--text-dim)', marginTop:4 }}>{sub}</div>}
        </div>
        <span style={{ fontSize:20, opacity:0.5 }}>{icon}</span>
      </div>
    </div>
  );
}

function RiskGauge({ score }) {
  const angle = ((score || 0) / 10) * 180;
  const r = 65, cx = 80, cy = 80;
  const toXY = deg => ({
    x: cx + r * Math.cos((Math.PI * (180 + deg)) / 180),
    y: cy + r * Math.sin((Math.PI * (180 + deg)) / 180),
  });
  const start = toXY(0), end = toXY(angle);
  const largeArc = angle > 180 ? 1 : 0;
  const color = score >= 8 ? '#EF4444' : score >= 6 ? '#F59E0B' : '#10B981';
  return (
    <svg width="160" height="90" viewBox="0 0 160 90">
      <path d={`M ${toXY(0).x} ${toXY(0).y} A ${r} ${r} 0 0 1 ${toXY(180).x} ${toXY(180).y}`}
        fill="none" stroke="var(--border)" strokeWidth="8" strokeLinecap="round"/>
      {angle > 0 && (
        <path d={`M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`}
          fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          style={{ filter:`drop-shadow(0 0 5px ${color})` }}/>
      )}
      <circle cx={cx} cy={cy} r="4" fill={color}/>
      <text x={cx} y={cy-16} textAnchor="middle" fill={color}
        style={{ fontFamily:'var(--font-mono)', fontSize:20, fontWeight:700 }}>
        {(score || 0).toFixed(1)}
      </text>
      <text x={cx} y={cy-3} textAnchor="middle" fill="var(--text-dim)"
        style={{ fontFamily:'var(--font-sans)', fontSize:8 }}>AVG RISK</text>
    </svg>
  );
}

export default function Overview({ posture }) {
  if (!posture) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
      height:300, color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>
      Loading posture data...
    </div>
  );

  const sev   = posture.severity_counts || {};
  const cloud = posture.cloud_breakdown || {};
  const chain = posture.kill_chain || {};
  const comp  = posture.compliance || {};

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:20, maxWidth:1200 }}>
      <div style={{ display:'flex', gap:12 }}>
        <StatCard label="Open Findings"  value={posture.total_open}      color="#EF4444" icon="⚠" sub="across all clouds"/>
        <StatCard label="Critical"       value={sev.CRITICAL || 0}       color="#EF4444" icon="🔴" sub="immediate action"/>
        <StatCard label="High"           value={sev.HIGH || 0}           color="#F59E0B" icon="🟠" sub="within 24 hours"/>
        <StatCard label="Avg Risk Score" value={posture.avg_risk_score}   color="#F59E0B" icon="◎" sub="out of 10.0"/>
        <StatCard label="Active Tactics" value={chain.total_tactics || 0} color="#8B5CF6" icon="⬡" sub="ATT&CK kill chain"/>
      </div>

      <div style={{ display:'flex', gap:16 }}>
        <div style={{ background:'var(--panel)', border:'1px solid var(--border)',
          borderRadius:8, padding:'20px 24px',
          display:'flex', flexDirection:'column', alignItems:'center', gap:12,
          flex:'0 0 200px' }}>
          <RiskGauge score={posture.avg_risk_score}/>
          <div style={{ width:'100%' }}>
            {Object.entries(sev).map(([s, c]) => c > 0 && (
              <div key={s} style={{ display:'flex', justifyContent:'space-between',
                alignItems:'center', marginBottom:6 }}>
                <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                  <div style={{ width:8, height:8, borderRadius:2, background:SEV_COLOR[s] }}/>
                  <span style={{ fontSize:11, color:'var(--text-sec)' }}>{s}</span>
                </div>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:11,
                  fontWeight:700, color:SEV_COLOR[s] }}>{c}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ background:'var(--panel)', border:'1px solid var(--border)',
          borderRadius:8, padding:'20px 24px', flex:1 }}>
          <div style={{ fontSize:11, color:'var(--text-sec)', textTransform:'uppercase',
            letterSpacing:1, marginBottom:14 }}>Cloud Coverage</div>
          <div style={{ display:'flex', gap:10, marginBottom:20 }}>
            {Object.entries(cloud).map(([c, d]) => (
              <div key={c} style={{ flex:1, background:'var(--surface)', borderRadius:8,
                padding:'12px 16px', borderLeft:`3px solid ${CLOUD_COLOR[c]||'#888'}` }}>
                <div style={{ fontFamily:'var(--font-mono)', fontSize:11,
                  color:CLOUD_COLOR[c]||'#888', fontWeight:700, marginBottom:6 }}>{c}</div>
                <div style={{ fontFamily:'var(--font-mono)', fontSize:22,
                  fontWeight:700, color:'var(--text)' }}>{d.total}</div>
                <div style={{ fontSize:11, color:'var(--text-dim)', marginTop:2 }}>
                  {d.critical > 0
                    ? <span style={{color:'var(--crimson)'}}>{d.critical} critical</span>
                    : 'open findings'}
                </div>
              </div>
            ))}
          </div>

          <div style={{ fontSize:11, color:'var(--text-sec)', textTransform:'uppercase',
            letterSpacing:1, marginBottom:10 }}>Compliance Posture</div>
          {Object.entries(comp).map(([fw, d]) => {
            const pct = d.pass_pct || 0;
            const col = pct >= 90 ? '#10B981' : pct >= 75 ? '#F59E0B' : '#EF4444';
            return (
              <div key={fw} style={{ marginBottom:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                  <span style={{ fontSize:11, color:'var(--text-sec)' }}>{fw}</span>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:11,
                    color:col, fontWeight:700 }}>{pct}%</span>
                </div>
                <div style={{ background:'var(--surface)', borderRadius:3, height:5 }}>
                  <div style={{ width:`${pct}%`, height:'100%', background:col,
                    borderRadius:3, transition:'width 1s ease' }}/>
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ background:'var(--panel)', border:'1px solid var(--border)',
          borderRadius:8, padding:'20px 24px', flex:'0 0 280px' }}>
          <div style={{ fontSize:11, color:'var(--text-sec)', textTransform:'uppercase',
            letterSpacing:1, marginBottom:14 }}>ATT&CK Kill Chain</div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:11,
            color:'var(--purple)', marginBottom:12 }}>
            {chain.total_tactics || 0} active tactic{chain.total_tactics !== 1 ? 's' : ''}
            {chain.highest_impact && (
              <span style={{ color:'var(--text-sec)' }}> → {chain.highest_impact}</span>
            )}
          </div>
          {(chain.steps || []).map(s => (
            <div key={s.tactic_id} style={{ display:'flex', alignItems:'center',
              gap:8, marginBottom:8 }}>
              <div style={{ width:22, height:22, borderRadius:4,
                background:'rgba(139,92,246,0.2)', border:'1px solid rgba(139,92,246,0.4)',
                display:'flex', alignItems:'center', justifyContent:'center',
                fontFamily:'var(--font-mono)', fontSize:9, color:'var(--purple)', fontWeight:700 }}>
                {s.order}
              </div>
              <div>
                <div style={{ fontSize:11, color:'var(--text)', fontWeight:500 }}>{s.tactic_name}</div>
                <div style={{ fontSize:10, color:'var(--text-dim)' }}>
                  {s.finding_count} finding{s.finding_count !== 1 ? 's' : ''}
                </div>
              </div>
            </div>
          ))}
          {chain.narrative && (
            <div style={{ marginTop:12, padding:'10px 12px',
              background:'rgba(139,92,246,0.08)', borderRadius:6,
              borderLeft:'2px solid var(--purple)',
              fontSize:10, color:'var(--text-sec)', lineHeight:1.5 }}>
              {chain.narrative.slice(0, 160)}...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
