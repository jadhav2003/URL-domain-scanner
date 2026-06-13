import { useLocation, useNavigate } from 'react-router-dom'
import { useEffect } from 'react'

export default function Results() {
  const { state } = useLocation()
  const navigate = useNavigate()
  const d = state?.data

  useEffect(() => {
    if (!d) navigate('/')
  }, [d, navigate])

  if (!d) return null

  const riskClass = d.risk_level === 'Safe' ? 'safe' : d.risk_level === 'Suspicious' ? 'suspicious' : 'dangerous'
  const riskColors = { safe: { bg: '#0d2119', border: '#238636', text: '#3fb950', pill: '#238636' },
    suspicious: { bg: '#2b1d00', border: '#d29922', text: '#e3b341', pill: '#d29922' },
    dangerous: { bg: '#2d0f0f', border: '#da3633', text: '#f85149', pill: '#da3633' } }
  const rc = riskColors[riskClass]

  const copyShareLink = () => {
    navigator.clipboard.writeText(`${window.location.origin}/share/${d.scan_id}`)
    alert('Share link copied!')
  }

  return (
    <div style={s.page}>
      <div style={s.container}>

        {/* Header */}
        <div style={s.header}>
          <div>
            <h1 style={s.h1}>Scan Result</h1>
            <span style={s.badge}>{d.url}</span>
          </div>
          <div style={s.btnGroup}>
            <a href={`http://127.0.0.1:5000/download-report/${d.url}`}
               style={s.pdfBtn} target="_blank" rel="noreferrer">
              📄 Download PDF
            </a>
            <button onClick={copyShareLink} style={s.outlineBtn}>🔗 Share</button>
            <button onClick={() => navigate('/')} style={s.outlineBtn}>← New Scan</button>
          </div>
        </div>

        {/* Risk Banner */}
        <div style={{ ...s.banner, background: rc.bg, border: `1px solid ${rc.border}` }}>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700, color: rc.text }}>
              {d.risk_level === 'Safe' ? '✅' : d.risk_level === 'Suspicious' ? '⚠️' : '🚨'} {d.risk_level}
            </div>
            <div style={{ fontSize: 13, color: '#8b949e', marginTop: 4 }}>
              Based on {d.flags?.length} indicator(s) checked
            </div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ ...s.pill, background: rc.pill }}>Risk Score: {d.risk_score}</div>
            <div style={{ fontSize: 13, color: '#8b949e', marginTop: 8 }}>
              Reputation: <span style={{ fontWeight: 700, color: d.reputation_score >= 70 ? '#3fb950' : d.reputation_score >= 40 ? '#e3b341' : '#f85149' }}>
                {d.reputation_score}/100
              </span>
            </div>
          </div>
        </div>

        {/* Row 1 */}
        <div style={s.grid}>
          <div style={s.card}>
            <div style={s.cardTitle}>Domain Info</div>
            {[['Registrar', d.registrar], ['IP Address', d.ip_address], ['Domain Age', d.domain_age]].map(([l, v]) => (
              <div key={l} style={s.infoRow}>
                <span style={s.label}>{l}</span>
                <span style={s.value}>{v}</span>
              </div>
            ))}
          </div>

          <div style={s.card}>
            <div style={s.cardTitle}>SSL Certificate</div>
            {d.ssl_info?.includes('Found') ? (
              <><p style={{ color: '#3fb950', fontWeight: 600 }}>✅ Certificate Found</p>
              <p style={{ color: '#8b949e', fontSize: 13, marginTop: 8 }}>HTTPS encryption is active</p></>
            ) : (
              <><p style={{ color: '#f85149', fontWeight: 600 }}>❌ No Certificate</p>
              <p style={{ color: '#8b949e', fontSize: 13, marginTop: 8 }}>Connection is not encrypted</p></>
            )}
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 12, color: '#8b949e', marginBottom: 4 }}>Reputation: {d.reputation_score}/100</div>
              <div style={{ background: '#21262d', borderRadius: 10, height: 10, overflow: 'hidden' }}>
                <div style={{ width: `${d.reputation_score}%`, height: 10, borderRadius: 10,
                  background: d.reputation_score >= 70 ? '#238636' : d.reputation_score >= 40 ? '#d29922' : '#da3633' }}/>
              </div>
            </div>
          </div>
        </div>

        {/* Threat Indicators */}
        <div style={{ ...s.card, marginBottom: 16 }}>
          <div style={s.cardTitle}>Threat Indicators</div>
          {d.flags?.length > 0 ? d.flags.map((f, i) => (
            <div key={i} style={{ ...s.infoRow, color: '#e3b341' }}>⚠️ {f}</div>
          )) : <div style={{ color: '#3fb950' }}>✅ No suspicious indicators detected</div>}
        </div>

        {/* Blacklist */}
        <div style={{ ...s.card, marginBottom: 16 }}>
          <div style={s.cardTitle}>Blacklist Check</div>
          <p style={{ color: d.is_blacklisted ? '#f85149' : '#3fb950', fontWeight: 700, marginBottom: 12 }}>
            {d.is_blacklisted ? '🚨 Found on a threat blacklist!' : '✅ Not found on any blacklist'}
          </p>
          {d.blacklist_results?.map((r, i) => (
            <div key={i} style={{ ...s.infoRow, color: r.includes('Found in') ? '#f85149' : r.includes('hosting') || r.includes('failed') ? '#e3b341' : '#3fb950' }}>
              {r}
            </div>
          ))}
        </div>

        {/* VirusTotal */}
        <div style={{ ...s.card, marginBottom: 16 }}>
          <div style={s.cardTitle}>VirusTotal Analysis</div>
          {d.vt_result?.error ? (
            <p style={{ color: '#e3b341' }}>⚠️ {d.vt_result.error}</p>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
                {[
                  { label: 'Harmless', val: d.vt_result?.harmless, color: '#3fb950', bg: '#0d2119', border: '#238636' },
                  { label: 'Malicious', val: d.vt_result?.malicious, color: '#f85149', bg: '#2d0f0f', border: '#da3633' },
                  { label: 'Suspicious', val: d.vt_result?.suspicious, color: '#e3b341', bg: '#2b1d00', border: '#d29922' },
                  { label: 'Undetected', val: d.vt_result?.undetected, color: '#8b949e', bg: '#161b22', border: '#30363d' },
                  { label: 'Total', val: d.vt_result?.total, color: '#58a6ff', bg: '#161b22', border: '#58a6ff' },
                ].map(({ label, val, color, bg, border }) => (
                  <div key={label} style={{ flex: 1, minWidth: 80, background: bg, border: `1px solid ${border}`, borderRadius: 8, padding: '14px 20px', textAlign: 'center' }}>
                    <div style={{ fontSize: 28, fontWeight: 700, color }}>{val}</div>
                    <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>{label}</div>
                  </div>
                ))}
              </div>
              {d.vt_result?.engines_flagged?.length > 0 ? (
                d.vt_result.engines_flagged.map((e, i) => (
                  <div key={i} style={{ color: '#f85149', fontSize: 13 }}>🚨 {e}</div>
                ))
              ) : <p style={{ color: '#3fb950', fontSize: 13 }}>✅ No engines flagged this URL</p>}
            </>
          )}
        </div>

        {/* Geo + DNS */}
        <div style={s.grid}>
          {d.geo_info && (
            <div style={s.card}>
              <div style={s.cardTitle}>Geolocation & ISP</div>
              {[['Country', d.geo_info.country], ['Region', d.geo_info.region],
                ['City', d.geo_info.city], ['ISP', d.geo_info.isp],
                ['Organisation', d.geo_info.org], ['Timezone', d.geo_info.timezone],
                ['Coordinates', `${d.geo_info.lat}, ${d.geo_info.lon}`]].map(([l, v]) => (
                <div key={l} style={s.infoRow}>
                  <span style={s.label}>{l}</span>
                  <span style={s.value}>{v}</span>
                </div>
              ))}
              <a href={`https://www.google.com/maps?q=${d.geo_info.lat},${d.geo_info.lon}`}
                 target="_blank" rel="noreferrer"
                 style={{ color: '#58a6ff', fontSize: 13, display: 'block', marginTop: 10 }}>
                📍 View on Google Maps
              </a>
            </div>
          )}
          <div style={s.card}>
            <div style={s.cardTitle}>DNS Records</div>
            {d.dns_records?.map((r, i) => (
              <div key={i} style={{ fontFamily: 'monospace', color: '#79c0ff', padding: '7px 0', borderBottom: '1px solid #21262d' }}>{r}</div>
            ))}
          </div>
        </div>

      </div>
    </div>
  )
}

const s = {
  page: { backgroundColor: '#0d1117', color: '#c9d1d9', fontFamily: "'Segoe UI', sans-serif", minHeight: '100vh', padding: '40px 20px' },
  container: { maxWidth: 820, margin: '0 auto' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 30, flexWrap: 'wrap', gap: 12 },
  h1: { fontSize: 22, color: '#fff', marginBottom: 6 },
  badge: { background: '#161b22', border: '1px solid #30363d', borderRadius: 6, padding: '4px 12px', fontSize: 13, color: '#58a6ff', fontFamily: 'monospace' },
  btnGroup: { display: 'flex', gap: 10, flexWrap: 'wrap' },
  pdfBtn: { background: '#238636', color: '#fff', textDecoration: 'none', padding: '8px 16px', borderRadius: 6, fontSize: 14, fontWeight: 600 },
  outlineBtn: { color: '#58a6ff', background: 'none', border: '1px solid #30363d', padding: '8px 16px', borderRadius: 6, fontSize: 14, cursor: 'pointer', fontFamily: 'inherit' },
  banner: { borderRadius: 10, padding: '20px 24px', marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 },
  pill: { padding: '6px 16px', borderRadius: 20, fontWeight: 700, fontSize: 15, color: '#fff', display: 'inline-block' },
  grid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 },
  card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: 20 },
  cardTitle: { fontSize: 11, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#8b949e', marginBottom: 14, borderLeft: '3px solid #58a6ff', paddingLeft: 8 },
  infoRow: { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #21262d', fontSize: 14 },
  label: { color: '#8b949e' },
  value: { color: '#c9d1d9', textAlign: 'right', wordBreak: 'break-all' },
}