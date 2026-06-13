import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const FLASK_URL = 'https://url-domain-scanner.onrender.com'

const messages = [
  "🔍 Scanning domain...",
  "🌐 Checking DNS records...",
  "🔒 Verifying SSL certificate...",
  "🛡️ Running blacklist checks...",
  "🦠 Querying VirusTotal engines...",
  "📍 Fetching geolocation data...",
  "📊 Calculating risk score..."
]

export default function Home() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [msgIndex, setMsgIndex] = useState(0)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleScan = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    const interval = setInterval(() => {
      setMsgIndex(i => (i + 1) % messages.length)
    }, 1800)

    try {
  const formData = new FormData()
  formData.append('url', url)

  console.log("Sending request to:", `${FLASK_URL}/scan`)

  const response = await axios.post(`${FLASK_URL}/api/scan`, formData)

  console.log("SUCCESS RESPONSE:", response)
  console.log("RESPONSE DATA:", response.data)

  clearInterval(interval)
  setLoading(false)

  navigate('/results', { state: { data: response.data } })

} catch (err) {

  console.log("FULL ERROR:", err)

  if (err.response) {
    console.log("Error Response:", err.response)
    console.log("Error Data:", err.response.data)
    console.log("Error Status:", err.response.status)
  }

  clearInterval(interval)
  setLoading(false)
  setError('Scan failed. Make sure Flask is running.')
}
  }

  return (
    <div style={styles.body}>
      {loading && (
        <div style={styles.overlay}>
          <div style={styles.spinner}></div>
          <div style={styles.spinnerText}>{messages[msgIndex]}</div>
          <div style={styles.spinnerSub}>Running WHOIS, DNS, SSL, Blacklist & VirusTotal checks</div>
        </div>
      )}

      <div style={styles.container}>
        <div style={styles.logo}>⚡ Threat Intelligence</div>
        <h1 style={styles.h1}>URL & Domain Scanner</h1>
        <p style={styles.subtitle}>Analyze any domain for phishing, malware, geolocation & DNS intelligence</p>

        <div style={styles.scanBox}>
          <form onSubmit={handleScan}>
            <div style={styles.inputRow}>
              <input
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="Enter domain or URL (e.g. google.com)"
                required
                style={styles.input}
              />
              <button type="submit" disabled={loading} style={styles.button}>
                🔍 Scan
              </button>
            </div>
          </form>

          {error && <p style={{ color: '#f85149', marginTop: 12 }}>{error}</p>}

          <div style={styles.features}>
            {['WHOIS Lookup','DNS Records','SSL Check','Phishing Detection','VirusTotal','Geolocation'].map(f => (
              <span key={f} style={styles.featureTag}>
                <span style={styles.dot}></span> {f}
              </span>
            ))}
          </div>

          <div style={{ marginTop: 16, textAlign: 'right' }}>
            <a href="/history" style={{ color: '#8b949e', fontSize: 13, textDecoration: 'none' }}>
              📋 View Scan History →
            </a>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        div[data-spinner] { animation: spin 0.9s linear infinite; }
      `}</style>
    </div>
  )
}

const styles = {
  body: {
    backgroundColor: '#0d1117',
    color: '#c9d1d9',
    fontFamily: "'Segoe UI', sans-serif",
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  overlay: {
    position: 'fixed', top: 0, left: 0,
    width: '100%', height: '100%',
    background: 'rgba(13,17,23,0.93)',
    zIndex: 999,
    display: 'flex', flexDirection: 'column',
    alignItems: 'center', justifyContent: 'center', gap: 20,
  },
  spinner: {
    width: 56, height: 56,
    border: '4px solid #30363d',
    borderTopColor: '#58a6ff',
    borderRadius: '50%',
    animation: 'spin 0.9s linear infinite',
  },
  spinnerText: { color: '#c9d1d9', fontSize: 17, fontWeight: 600 },
  spinnerSub: { color: '#8b949e', fontSize: 13 },
  container: { textAlign: 'center', padding: 40, maxWidth: 700, width: '100%' },
  logo: { fontSize: 14, letterSpacing: 4, color: '#58a6ff', textTransform: 'uppercase', marginBottom: 12 },
  h1: { fontSize: 32, fontWeight: 700, color: '#ffffff', marginBottom: 10 },
  subtitle: { color: '#8b949e', fontSize: 15, marginBottom: 32 },
  scanBox: { background: '#161b22', border: '1px solid #30363d', borderRadius: 12, padding: 32 },
  inputRow: { display: 'flex', gap: 12 },
  input: {
    flex: 1, background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 8, padding: '14px 18px', color: '#c9d1d9',
    fontSize: 15, outline: 'none',
  },
  button: {
    background: '#238636', color: '#fff', border: 'none',
    borderRadius: 8, padding: '14px 28px', fontSize: 15,
    fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap',
  },
  features: { display: 'flex', justifyContent: 'center', gap: 24, marginTop: 28, flexWrap: 'wrap' },
  featureTag: { fontSize: 12, color: '#8b949e', display: 'flex', alignItems: 'center', gap: 6 },
  dot: { width: 6, height: 6, background: '#238636', borderRadius: '50%', display: 'inline-block' },
}