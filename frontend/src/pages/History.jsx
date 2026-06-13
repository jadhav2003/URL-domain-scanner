import { useState, useEffect } from 'react'
import axios from 'axios'

const FLASK_URL = 'http://127.0.0.1:5000'

export default function History() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    axios.get(`${FLASK_URL}/api/history`)
      .then(res => { setScans(res.data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  const badgeColor = (level) => {
    if (level === 'Safe') return { bg: '#0d2119', color: '#3fb950', border: '#238636' }
    if (level === 'Suspicious') return { bg: '#2b1d00', color: '#e3b341', border: '#d29922' }
    return { bg: '#2d0f0f', color: '#f85149', border: '#da3633' }
  }

  const safe = scans.filter(s => s.risk_level === 'Safe').length
  const suspicious = scans.filter(s => s.risk_level === 'Suspicious').length
  const dangerous = scans.filter(s => s.risk_level === 'Dangerous').length

  return (
    <div style={{ backgroundColor: '#0d1117', minHeight: '100vh', padding: '40px 20px', fontFamily: "'Segoe UI', sans-serif", color: '#c9d1d9' }}>
      <div style={{ maxWidth: 1000, margin: '0 auto' }}>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
          <div>
            <h1 style={{ fontSize: 22, color: '#fff' }}>📋 Scan History</h1>
            <p style={{ color: '#8b949e', fontSize: 14, marginTop: 4 }}>All previously scanned domains</p>
          </div>
          <a href="/" style={{ color: '#58a6ff', textDecoration: 'none', border: '1px solid #30363d', padding: '8px 16px', borderRadius: 6, fontSize: 14 }}>
            ← New Scan
          </a>
        </div>

        {/* Stats */}
        <div style={{ display: 'flex', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
          {[
            { label: 'Total Scans', val: scans.length, color: '#fff' },
            { label: 'Safe', val: safe, color: '#3fb950' },
            { label: 'Suspicious', val: suspicious, color: '#e3b341' },
            { label: 'Dangerous', val: dangerous, color: '#f85149' },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: '16px 24px', flex: 1, minWidth: 140, textAlign: 'center' }}>
              <div style={{ fontSize: 28, fontWeight: 700, color }}>{val}</div>
              <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>{label}</div>
            </div>
          ))}
        </div>

        {loading ? <p style={{ color: '#8b949e' }}>Loading...</p> : scans.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 60, color: '#8b949e' }}>
            <p style={{ fontSize: 40 }}>🔍</p>
            <p style={{ marginTop: 12 }}>No scans yet. Go scan something!</p>
          </div>
        ) : (
          <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 10, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#21262d' }}>
                  {['#','URL','IP Address','Country','ISP','Risk Level','Score','Scanned At'].map(h => (
                    <th key={h} style={{ padding: '12px 16px', textAlign: 'left', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, color: '#8b949e', borderBottom: '1px solid #30363d' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map((scan, i) => {
                  const bc = badgeColor(scan.risk_level)
                  return (
                    <tr key={scan.id} style={{ borderBottom: '1px solid #21262d' }}>
                      <td style={{ padding: '12px 16px', color: '#8b949e' }}>{i + 1}</td>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#58a6ff', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{scan.url}</td>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace' }}>{scan.ip_address}</td>
                      <td style={{ padding: '12px 16px' }}>{scan.country}</td>
                      <td style={{ padding: '12px 16px' }}>{scan.isp}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ background: bc.bg, color: bc.color, border: `1px solid ${bc.border}`, padding: '3px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600 }}>
                          {scan.risk_level}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>{scan.risk_score}</td>
                      <td style={{ padding: '12px 16px', color: '#8b949e', fontSize: 13 }}>{scan.scanned_at}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}