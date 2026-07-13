import { useState, useEffect } from 'react';
import Overview from './components/Overview';
import Findings from './components/Findings';
import MitreHeatmap from './components/MitreHeatmap';
import Compliance from './components/Compliance';
import { getPosture, triggerScan } from './api';
import './index.css';

const NAV = [
  { id: 'overview',   label: 'Overview',   icon: '◈' },
  { id: 'findings',   label: 'Findings',   icon: '⚠' },
  { id: 'mitre',      label: 'ATT&CK Map', icon: '⬡' },
  { id: 'compliance', label: 'Compliance', icon: '✓' },
];

export default function App() {
  const [tab, setTab]           = useState('overview');
  const [posture, setPosture]   = useState(null);
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState('--');

  useEffect(() => { loadPosture(); }, []);

  async function loadPosture() {
    try {
      const { data } = await getPosture();
      setPosture(data);
      setLastScan(new Date().toLocaleTimeString());
    } catch (e) {
      console.error('Failed to load posture:', e);
    }
  }

  async function handleScan() {
    setScanning(true);
    try {
      await triggerScan('358487322954');
      setTimeout(() => { loadPosture(); setScanning(false); }, 3000);
    } catch { setScanning(false); }
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', overflow:'hidden' }}>
      <header style={{
        display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 24px', height:56, flexShrink:0,
        background:'var(--surface)', borderBottom:'1px solid var(--border)',
        position:'sticky', top:0, zIndex:100,
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{
            width:30, height:30, borderRadius:6,
            background:'var(--cyan-dim)', border:'1px solid rgba(0,212,255,0.4)',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:16, color:'var(--cyan)',
          }}>⬡</div>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:15,
            fontWeight:700, color:'var(--cyan)' }}>CloudSentinel</span>
          <span style={{ fontSize:10, color:'var(--text-dim)',
            background:'var(--panel)', padding:'2px 7px', borderRadius:10 }}>CSPM v2.1</span>
        </div>

        <nav style={{ display:'flex', gap:4 }}>
          {NAV.map(n => (
            <button key={n.id} onClick={() => setTab(n.id)} style={{
              background: tab===n.id ? 'var(--cyan-dim)' : 'transparent',
              border: tab===n.id ? '1px solid rgba(0,212,255,0.35)' : '1px solid transparent',
              borderRadius:6, padding:'6px 14px', cursor:'pointer',
              color: tab===n.id ? 'var(--cyan)' : 'var(--text-sec)',
              fontFamily:'var(--font-sans)', fontSize:12, fontWeight:500,
              transition:'all 0.15s',
            }}>
              {n.icon} {n.label}
            </button>
          ))}
        </nav>

        <div style={{ display:'flex', alignItems:'center', gap:14 }}>
          {posture && (
            <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-dim)' }}>
              <span style={{ color:'var(--text-sec)' }}>open </span>
              <span style={{ color:'var(--crimson)', fontWeight:700 }}>{posture.total_open}</span>
              <span style={{ color:'var(--text-sec)', marginLeft:10 }}>risk </span>
              <span style={{ color:'var(--amber)', fontWeight:700 }}>{posture.avg_risk_score}</span>
            </div>
          )}
          <span style={{ fontSize:11, color:'var(--text-dim)' }}>
            {lastScan !== '--' && <>last scan <span style={{color:'var(--green)'}}>{lastScan}</span></>}
          </span>
          <button onClick={handleScan} disabled={scanning} style={{
            background:'var(--cyan-dim)', border:'1px solid rgba(0,212,255,0.4)',
            borderRadius:6, padding:'7px 14px', cursor:'pointer',
            color:'var(--cyan)', fontFamily:'var(--font-mono)', fontSize:11, fontWeight:700,
            opacity: scanning ? 0.6 : 1,
          }}>
            {scanning ? '⟳ Scanning...' : '▶ Run Scan'}
          </button>
        </div>
      </header>

      <main style={{ flex:1, overflowY:'auto', padding:24 }}>
        {tab === 'overview'   && <Overview posture={posture} onRefresh={loadPosture}/>}
        {tab === 'findings'   && <Findings/>}
        {tab === 'mitre'      && <MitreHeatmap/>}
        {tab === 'compliance' && <Compliance/>}
      </main>
    </div>
  );
}
