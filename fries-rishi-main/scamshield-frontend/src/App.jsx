import { useState, useRef, useEffect } from 'react'
import * as pdfjsLib from 'pdfjs-dist'
import { scanOffer, getStats, getHistory } from './api/client'

pdfjsLib.GlobalWorkerOptions.workerSrc =
  `https://unpkg.com/pdfjs-dist@3.11.174/build/pdf.worker.min.js`
async function extractPDFText(file) {
  const buf  = await file.arrayBuffer()
  const pdf  = await pdfjsLib.getDocument({ data: buf }).promise
  let text   = ''
  for (let i = 1; i <= pdf.numPages; i++) {
    const page    = await pdf.getPage(i)
    const content = await page.getTextContent()
    text += content.items.map(s => s.str).join(' ') + '\n'
  }
  return text
}

const TABS = ['JOB URL', 'E-MAIL', 'SALARY', 'COMPANY', 'STATS', 'HISTORY']

const VERDICT_COLOR = {
  VERIFIED:   '#16a34a',
  UNVERIFIED: '#d97706',
  SUSPICIOUS: '#ea580c',
  SCAM:       '#dc2626',
}

const SCORE_BG = score =>
  score >= 80 ? '#dcfce7' : score >= 55 ? '#fef9c3' : score >= 30 ? '#ffedd5' : '#fee2e2'
const SCORE_TEXT = score =>
  score >= 80 ? '#166534' : score >= 55 ? '#854d0e' : score >= 30 ? '#9a3412' : '#991b1b'

export default function App() {
  const [activeTab, setActiveTab]   = useState('JOB URL')
  const [messages, setMessages]     = useState([])
  const [input, setInput]           = useState('')
  const [jobRole, setJobRole]       = useState('')
  const [loading, setLoading]       = useState(false)
  const [loadingStep, setLoadingStep] = useState(0)
  const [stats, setStats]           = useState(null)
  const [history, setHistory]       = useState([])
  const fileRef = useRef()
  const navRef = useRef()
  const [pillStyle, setPillStyle] = useState({ width: 0, transform: 'translateX(0px)' })

  useEffect(() => {
    if (!navRef.current) return
    const activeBtn = navRef.current.querySelector('[data-active="true"]')
    if (activeBtn) {
      setPillStyle({
        width: activeBtn.offsetWidth,
        transform: `translateX(${activeBtn.offsetLeft}px)`
      })
    }
  }, [activeTab])

  const LOADING_STEPS = [
    'Establishing secure connection...',
    'Analyzing WHOIS & SSL infrastructure...',
    'Running NLP threat detection...',
    'Correlating fraud signals...',
  ]

  const pushMsg = (role, content) =>
    setMessages(prev => [...prev, { role, content, id: Date.now() + Math.random() }])

  const handleSend = async (text, extra = {}) => {
    const userText = text || input.trim()
    if (!userText && !extra.offer_text) return
    setInput('')
    pushMsg('user', userText || '[PDF uploaded]')
    setLoading(true)
    setLoadingStep(0)

    const stepInterval = setInterval(() =>
      setLoadingStep(s => Math.min(s + 1, LOADING_STEPS.length - 1)), 800)

    const payload = {
      job_url:         activeTab === 'JOB URL' ? userText : 'N/A',
      recruiter_email: activeTab === 'E-MAIL'  ? userText : '',
      salary_offered:  activeTab === 'SALARY'  ? parseFloat(userText.replace(/[^0-9.]/g, '')) || 0 : 0,
      company_claimed: activeTab === 'COMPANY' ? userText : 'Unknown',
      offer_text:      extra.offer_text || userText || '',
      phone_number:    '',
    }

    try {
      const { data } = await scanOffer(payload)
      clearInterval(stepInterval)
      setLoading(false)
      pushMsg('result', data)
    } catch {
      clearInterval(stepInterval)
      setLoading(false)
      pushMsg('error', 'Could not reach backend. Make sure FastAPI is running on port 8000.')
    }
  }

  const handlePDF = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    try {
      const text = await extractPDFText(file)
      await handleSend(`PDF: ${file.name}`, { offer_text: text })
    } catch {
      pushMsg('error', 'PDF extraction failed.')
    }
  }

  const handleTabChange = async (tab) => {
    setActiveTab(tab)
    setMessages([])
    if (tab === 'STATS') {
      try { const r = await getStats(); setStats(r.data) } catch { setStats(null) }
    }
    if (tab === 'HISTORY') {
      try { const r = await getHistory(20); setHistory(r.data) } catch { setHistory([]) }
    }
  }

  const handleNewChat = () => { setMessages([]); setInput('') }

  const isDataTab = activeTab === 'STATS' || activeTab === 'HISTORY'
  const isEmpty   = messages.length === 0

  return (
    <div style={{
      minHeight: '100vh', background: '#f3f4f6',
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    }}>

      {/* Top nav */}
      <div 
        ref={navRef}
        style={{
          position: 'sticky', top: 24, zIndex: 50,
          marginTop: 24, 
          background: 'rgba(255, 255, 255, 0.7)', 
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          borderRadius: 50,
          padding: '6px 8px', display: 'flex', gap: 4,
          boxShadow: '0 4px 16px rgba(0,0,0,0.08), inset 0 0 0 1px rgba(255,255,255,0.4)'
        }}
      >
        <div style={{
          position: 'absolute', top: 6, bottom: 6, left: 0,
          background: '#111827', borderRadius: 50,
          transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
          ...pillStyle
        }} />

        {TABS.map(tab => (
          <button 
            key={tab} 
            data-active={activeTab === tab}
            onClick={() => handleTabChange(tab)} 
            style={{
              position: 'relative', zIndex: 1,
              padding: '8px 20px', borderRadius: 50, border: 'none',
              cursor: 'pointer', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em',
              transition: 'color .4s cubic-bezier(0.4, 0, 0.2, 1)',
              background: 'transparent',
              color: activeTab === tab ? '#fff' : '#6b7280',
            }}
          >
            {tab === 'E-MAIL' ? 'E-MAIL AUDIT' : tab}
          </button>
        ))}
      </div>

      {/* Main area */}
      <div style={{
        flex: 1, width: '100%', maxWidth: 720,
        display: 'flex', flexDirection: 'column',
        padding: '0 16px', marginTop: 16
      }}>

        {/* STATS TAB */}
        {activeTab === 'STATS' && (
          <div style={{ marginTop: 24 }}>
            {!stats ? (
              <p style={{ textAlign: 'center', color: '#9ca3af', fontSize: 14 }}>Loading stats...</p>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {[
                  { label: 'Total Scans',  value: stats.total_checks.toLocaleString(), color: '#111827' },
                  { label: 'Scams Caught', value: stats.scams_caught.toLocaleString(), color: '#dc2626' },
                  { label: 'Suspicious',   value: stats.suspicious.toLocaleString(),   color: '#ea580c' },
                  { label: 'Scam Rate',    value: `${stats.scam_rate_pct}%`,           color: '#d97706' },
                ].map(c => (
                  <div key={c.label} style={{
                    background: '#fff', borderRadius: 16, padding: '20px 24px',
                    boxShadow: '0 1px 4px rgba(0,0,0,0.06)'
                  }}>
                    <div style={{ fontSize: 12, color: '#9ca3af', marginBottom: 8, fontWeight: 600, letterSpacing: '0.05em' }}>{c.label.toUpperCase()}</div>
                    <div style={{ fontSize: 32, fontWeight: 800, color: c.color }}>{c.value}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* HISTORY TAB */}
        {activeTab === 'HISTORY' && (
          <div style={{ marginTop: 24 }}>
            <div style={{ background: '#fff', borderRadius: 16, overflow: 'hidden', boxShadow: '0 1px 4px rgba(0,0,0,0.06)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #f3f4f6' }}>
                    {['ID', 'Company', 'Score', 'Verdict', 'Time'].map(h => (
                      <th key={h} style={{ padding: '12px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#9ca3af', letterSpacing: '0.05em' }}>{h.toUpperCase()}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0
                    ? <tr><td colSpan={5} style={{ padding: 32, textAlign: 'center', color: '#9ca3af' }}>No history yet</td></tr>
                    : history.map(r => (
                      <tr key={r.id} style={{ borderBottom: '1px solid #f9fafb' }}>
                        <td style={{ padding: '12px 16px', color: '#6b7280', fontSize: 11 }}>{r.id}</td>
                        <td style={{ padding: '12px 16px', color: '#111827', fontWeight: 500 }}>{r.company}</td>
                        <td style={{ padding: '12px 16px' }}>
                          <span style={{
                            background: SCORE_BG(r.score), color: SCORE_TEXT(r.score),
                            padding: '2px 10px', borderRadius: 50, fontSize: 12, fontWeight: 600
                          }}>{r.score}</span>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <span style={{
                            background: SCORE_BG(r.score), color: SCORE_TEXT(r.score),
                            padding: '2px 10px', borderRadius: 50, fontSize: 11, fontWeight: 700
                          }}>{r.verdict}</span>
                        </td>
                        <td style={{ padding: '12px 16px', color: '#9ca3af', fontSize: 11 }}>{r.ts}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* CHAT AREA */}
        {!isDataTab && (
          <>
            {activeTab === 'E-MAIL' && (
                <div style={{ marginTop: 24, display: 'flex', justifyContent: 'center' }}>
                  <div style={{
                    background: '#fff', borderRadius: 24, padding: '32px', width: '100%', maxWidth: 540,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.05), inset 0 0 0 1px #f3f4f6'
                  }}>
                    <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 24 }}>
                      <div>
                        <h2 style={{ fontSize: 20, fontWeight: 800, color: '#111827', margin: 0 }}>E-mail Audit</h2>
                        <p style={{ fontSize: 14, color: '#6b7280', margin: '4px 0 0', fontWeight: 500 }}>
                          Analyze suspicious email text for fraud signals.
                        </p>
                      </div>
                    </div>
                    
                    <textarea 
                      value={input}
                      onChange={e => setInput(e.target.value)}
                      placeholder="Paste email content here..."
                      style={{
                        width: '100%', minHeight: 80, padding: 16, borderRadius: 16,
                        border: '1px solid #e5e7eb', background: '#f9fafb',
                        fontSize: 15, color: '#111827', outline: 'none', resize: 'none',
                        fontFamily: 'inherit'
                      }}
                    />
                    
                    <button 
                      onClick={() => handleSend()}
                      disabled={loading || !input.trim()}
                      style={{
                        width: '100%', marginTop: 24, padding: 16, borderRadius: 12,
                        background: loading || !input.trim() ? '#d1d5db' : '#9ca3af',
                        border: 'none', color: '#fff', fontSize: 13, fontWeight: 800,
                        cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                        display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8,
                        letterSpacing: '0.05em'
                      }}
                    >
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <path d="M3 8V5a2 2 0 0 1 2-2h3 M21 8V5a2 2 0 0 0-2-2h-3 M3 16v3a2 2 0 0 0 2 2h3 M21 16v3a2 2 0 0 1-2 2h-3"/>
                        <circle cx="12" cy="12" r="3"/>
                        <line x1="14" y1="14" x2="17" y2="17"/>
                      </svg>
                      {loading ? 'ANALYZING...' : 'ANALYZE EMAIL'}
                    </button>
                  </div>
                </div>
            )}
            
            {activeTab === 'SALARY' && (
                <div style={{ marginTop: 24, display: 'flex', justifyContent: 'center' }}>
                  <div style={{
                    background: '#fff', borderRadius: 24, padding: '32px', width: '100%', maxWidth: 640,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.05), inset 0 0 0 1px #f3f4f6'
                  }}>
                    <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 32 }}>
                      <div>
                        <h2 style={{ fontSize: 22, fontWeight: 800, color: '#111827', margin: 0 }}>Salary Calibration</h2>
                        <p style={{ fontSize: 13, color: '#6b7280', margin: '4px 0 0', fontWeight: 500 }}>
                          Verify if compensation is realistic.
                        </p>
                      </div>
                    </div>
                    
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 800, color: '#9ca3af', marginBottom: 8, letterSpacing: '0.05em' }}>SALARY OFFERED</div>
                        <input 
                          value={input}
                          onChange={e => setInput(e.target.value)}
                          placeholder="e.g. $12,000 / month"
                          style={{
                            width: '100%', padding: '14px 16px', borderRadius: 12,
                            border: '1px solid #e5e7eb', background: '#f9fafb',
                            fontSize: 14, color: '#111827', outline: 'none'
                          }}
                        />
                      </div>
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 800, color: '#9ca3af', marginBottom: 8, letterSpacing: '0.05em' }}>JOB ROLE</div>
                        <input 
                          value={jobRole}
                          onChange={e => setJobRole(e.target.value)}
                          placeholder="e.g. Data Entry"
                          style={{
                            width: '100%', padding: '14px 16px', borderRadius: 12,
                            border: '1px solid #e5e7eb', background: '#f9fafb',
                            fontSize: 14, color: '#111827', outline: 'none'
                          }}
                        />
                      </div>
                    </div>
                    
                    <button 
                      onClick={() => {
                        const salaryText = input.trim();
                        const roleText = jobRole.trim() || 'Unknown Role';
                        handleSend(`${salaryText} (${roleText})`, { offer_text: `Role: ${roleText}` });
                      }}
                      disabled={loading || !input.trim()}
                      style={{
                        width: '100%', padding: '16px', borderRadius: 12,
                        background: loading || !input.trim() ? '#d1d5db' : '#111827',
                        border: 'none', color: '#fff', fontSize: 13, fontWeight: 800,
                        cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                        display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8,
                        letterSpacing: '0.05em'
                      }}
                    >
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                      </svg>
                      {loading ? 'CALIBRATING...' : 'CHECK ANOMALY COEFFICIENT'}
                    </button>
                  </div>
                </div>
            )}

            {activeTab === 'COMPANY' && (
                <div style={{ marginTop: 24, display: 'flex', justifyContent: 'center' }}>
                  <div style={{
                    background: '#fff', borderRadius: 24, padding: '32px', width: '100%', maxWidth: 640,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.05), inset 0 0 0 1px #f3f4f6'
                  }}>
                    <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 32 }}>
                      <div style={{
                        width: 56, height: 56, borderRadius: 16, background: '#fff',
                        boxShadow: '0 4px 12px rgba(255, 200, 200, 0.4), inset 0 0 0 1px #fee2e2',
                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                      }}>
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#111827" strokeWidth="1.5">
                          <path d="M3 21h18"></path>
                          <path d="M9 8h1"></path>
                          <path d="M9 12h1"></path>
                          <path d="M9 16h1"></path>
                          <path d="M14 8h1"></path>
                          <path d="M14 12h1"></path>
                          <path d="M14 16h1"></path>
                          <path d="M5 21V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16"></path>
                        </svg>
                      </div>
                      <div>
                        <h2 style={{ fontSize: 22, fontWeight: 800, color: '#111827', margin: 0 }}>Company Verification</h2>
                        <p style={{ fontSize: 13, color: '#6b7280', margin: '4px 0 0', fontWeight: 500 }}>
                          Verify legal existence and reputation.
                        </p>
                      </div>
                    </div>
                    
                    <div style={{ position: 'relative', marginBottom: 24 }}>
                      <div style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' }}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M3 21h18"></path>
                          <path d="M5 21V7l8-4v18"></path>
                          <path d="M19 21V11l-6-2"></path>
                          <path d="M9 9v.01"></path>
                          <path d="M9 13v.01"></path>
                          <path d="M9 17v.01"></path>
                        </svg>
                      </div>
                      <input 
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        placeholder="Search official registry..."
                        style={{
                          width: '100%', padding: '16px 16px 16px 48px', borderRadius: 12,
                          border: '1px solid #e5e7eb', background: '#f9fafb',
                          fontSize: 15, color: '#111827', outline: 'none',
                          fontFamily: 'inherit'
                        }}
                      />
                    </div>
                    
                    <button 
                      onClick={() => handleSend(input.trim())}
                      disabled={loading || !input.trim()}
                      style={{
                        width: '100%', padding: '16px', borderRadius: 12,
                        background: loading || !input.trim() ? '#d1d5db' : '#9ca3af',
                        border: 'none', color: '#fff', fontSize: 13, fontWeight: 800,
                        cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                        display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8,
                        letterSpacing: '0.05em'
                      }}
                    >
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                      </svg>
                      {loading ? 'CROSS-CHECKING...' : 'CROSS-CHECK REGISTRIES'}
                    </button>
                  </div>
                </div>
            )}

            {(isEmpty && activeTab !== 'E-MAIL' && activeTab !== 'SALARY' && activeTab !== 'COMPANY') ? (
                <div style={{
                  flex: 1, display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center',
                  minHeight: '60vh', gap: 12, textAlign: 'center'
                }}>
                  <div style={{
                    width: 56, height: 56, borderRadius: '50%',
                    background: '#fff', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
                  }}>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#111827" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                      <circle cx="11" cy="11" r="3" fill="#111827" stroke="none"/>
                    </svg>
                  </div>
                  <h2 style={{ fontSize: 20, fontWeight: 700, color: '#111827', margin: 0 }}>New Investigation</h2>
                  <p style={{ fontSize: 14, color: '#9ca3af', margin: 0, maxWidth: 300, lineHeight: 1.6 }}>
                    Paste a job URL or upload a PDF offer letter to begin analysis.
                  </p>
                  <button onClick={handleNewChat} style={{
                    marginTop: 8, padding: '10px 24px', borderRadius: 50,
                    border: '1.5px solid #e5e7eb', background: '#fff',
                    fontSize: 13, fontWeight: 600, color: '#374151',
                    cursor: 'pointer', letterSpacing: '0.02em'
                  }}>+ NEW CHAT</button>
                </div>
              ) : (!isEmpty && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 16, paddingTop: 24, paddingBottom: 120 }}>
                {messages.map(msg => (
                  <div key={msg.id}>

                    {/* User bubble */}
                    {msg.role === 'user' && (
                      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <div style={{
                          background: '#111827', color: '#fff',
                          borderRadius: '18px 18px 4px 18px',
                          padding: '12px 18px', maxWidth: '70%', fontSize: 14, lineHeight: 1.5
                        }}>{msg.content}</div>
                      </div>
                    )}

                    {/* Error bubble */}
                    {msg.role === 'error' && (
                      <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                        <div style={{
                          background: '#fee2e2', color: '#991b1b',
                          borderRadius: '18px 18px 18px 4px',
                          padding: '12px 18px', maxWidth: '80%', fontSize: 14
                        }}>{msg.content}</div>
                      </div>
                    )}

                    {/* Result card */}
                    {msg.role === 'result' && (() => {
                      const d = msg.content
                      const color = VERDICT_COLOR[d.verdict] || '#6b7280'
                      const signals = d.signals?.cyber_signals?.filter(s => s.flag) || []
                      return (
                        <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                          <div style={{
                            background: '#fff', borderRadius: '18px 18px 18px 4px',
                            padding: '20px 24px', maxWidth: '85%',
                            boxShadow: '0 2px 12px rgba(0,0,0,0.08)',
                            minWidth: 300
                          }}>
                            {/* Score row */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
                              <div style={{
                                width: 64, height: 64, borderRadius: '50%',
                                background: SCORE_BG(d.trust_score),
                                display: 'flex', flexDirection: 'column',
                                alignItems: 'center', justifyContent: 'center', flexShrink: 0
                              }}>
                                <span style={{ fontSize: 22, fontWeight: 800, color: SCORE_TEXT(d.trust_score) }}>{d.trust_score}</span>
                                <span style={{ fontSize: 8, color: SCORE_TEXT(d.trust_score), letterSpacing: '0.1em', fontWeight: 600 }}>TRUST</span>
                              </div>
                              <div>
                                <div style={{
                                  display: 'inline-block', padding: '3px 12px',
                                  borderRadius: 50, fontSize: 11, fontWeight: 700,
                                  letterSpacing: '0.08em',
                                  background: color + '18', color, marginBottom: 6
                                }}>{d.verdict}</div>
                                <p style={{ fontSize: 13, color: '#6b7280', margin: 0, lineHeight: 1.5 }}>{d.summary}</p>
                              </div>
                            </div>

                            {/* Signals */}
                            {signals.length > 0 && (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                                {signals.map((s, i) => (
                                  <div key={i} style={{
                                    background: '#fef2f2', borderLeft: '3px solid #dc2626',
                                    borderRadius: '0 8px 8px 0', padding: '8px 12px'
                                  }}>
                                    <div style={{ fontSize: 10, color: '#9ca3af', fontWeight: 600, marginBottom: 2, letterSpacing: '0.08em' }}>{s.category}</div>
                                    <div style={{ fontSize: 12, color: '#374151' }}>{s.reason}</div>
                                  </div>
                                ))}
                              </div>
                            )}

                            {signals.length === 0 && (
                              <div style={{
                                background: '#f0fdf4', borderLeft: '3px solid #16a34a',
                                borderRadius: '0 8px 8px 0', padding: '8px 12px', marginBottom: 14,
                                fontSize: 12, color: '#166534'
                              }}>✓ No threat signals detected</div>
                            )}

                            {/* Recommendations */}
                            {d.recommendations?.length > 0 && (
                              <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: '#9ca3af', letterSpacing: '0.08em', marginBottom: 8 }}>RECOMMENDATIONS</div>
                                {d.recommendations.map((r, i) => (
                                  <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: '#374151', marginBottom: 6, lineHeight: 1.5 }}>
                                    <span style={{ color: '#111827', fontWeight: 700, flexShrink: 0 }}>→</span> {r}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      )
                    })()}
                  </div>
                ))}

                {/* Loading indicator */}
                {loading && (
                  <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                    <div style={{
                      background: '#fff', borderRadius: '18px 18px 18px 4px',
                      padding: '16px 20px', boxShadow: '0 2px 8px rgba(0,0,0,0.06)'
                    }}>
                      <div style={{ fontSize: 12, color: '#9ca3af', marginBottom: 4 }}>
                        {LOADING_STEPS[loadingStep]}
                      </div>
                      <div style={{ display: 'flex', gap: 4 }}>
                        {[0,1,2].map(i => (
                          <div key={i} style={{
                            width: 6, height: 6, borderRadius: '50%', background: '#d1d5db',
                            animation: `bounce 1.2s ${i * 0.2}s infinite`
                          }}/>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </>
        )}
      </div>

      {/* Bottom input bar — only on chat tabs */}
      {(!isDataTab && activeTab !== 'E-MAIL' && activeTab !== 'SALARY' && activeTab !== 'COMPANY') && (
        <div style={{
          position: 'fixed', bottom: 0, left: 0, right: 0,
          padding: '16px 16px 24px',
          background: 'linear-gradient(to top, #f3f4f6 70%, transparent)'
        }}>
          <div style={{
            maxWidth: 720, margin: '0 auto',
            background: '#fff', borderRadius: 50,
            boxShadow: '0 2px 16px rgba(0,0,0,0.1)',
            display: 'flex', alignItems: 'center', padding: '8px 8px 8px 20px', gap: 8
          }}>
            <input type="file" accept=".pdf" ref={fileRef} style={{ display: 'none' }} onChange={handlePDF} />
            <button onClick={() => fileRef.current.click()} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              padding: 4, color: '#9ca3af', display: 'flex', alignItems: 'center'
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66L9.41 17.41a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
              </svg>
            </button>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !loading && handleSend()}
              placeholder={`Paste a job URL, recruiter email, or offer details...`}
              style={{
                flex: 1, border: 'none', outline: 'none', fontSize: 14,
                color: '#111827', background: 'transparent',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
              }}
            />
            <button onClick={() => handleSend()} disabled={loading || !input.trim()} style={{
              width: 40, height: 40, borderRadius: '50%',
              background: loading || !input.trim() ? '#e5e7eb' : '#111827',
              border: 'none', cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'background .2s', flexShrink: 0
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5">
                <path d="M5 12h14M12 5l7 7-7 7"/>
              </svg>
            </button>
          </div>
        </div>
      )}

      <style>{`
        @keyframes bounce {
          0%, 80%, 100% { transform: scale(0); }
          40% { transform: scale(1); }
        }
        * { box-sizing: border-box; }
        body { margin: 0; }
      `}</style>
    </div>
  )
}