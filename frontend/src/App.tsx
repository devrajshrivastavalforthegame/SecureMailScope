import { useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  Upload,
  FileSearch,
  LockKeyhole,
  BrainCircuit,
  CircleCheck,
  CircleX,
  AlertTriangle,
  Activity,
  Database,
  Fingerprint,
  Server,
  ChevronRight,
} from 'lucide-react'
import './App.css'

type Finding = {
  id: string
  severity: string
  title: string
  description: string
  remediation: string
  evidence_packets: number[]
  confidence: string
}

type Session = {
  session_id: string
  protocol: string
  endpoints: string[]
  packet_count: number
  packet_numbers: number[]
  starttls: {
    advertised: boolean
    requested: boolean
    accepted: boolean
    upgraded: boolean
    failed: boolean
    final_state: string
    evidence: {
      advertised_packets: number[]
      requested_packets: number[]
      accepted_packets: number[]
      tls_packets: number[]
    }
  }
  tls: {
    tls_detected: boolean
    record_count: number
    negotiated_version: string | null
    selected_cipher_suite: string | null
    key_exchange: string | null
    forward_secrecy: boolean
    server_name: string | null
    supported_versions: string[]
    certificate?: {
      subject: string
      issuer: string
      common_name: string
      san_dns_names: string[]
      expired: boolean
      sha256_fingerprint: string
    }
  }
  ml?: {
    model: string
    classification: string
    is_anomaly: boolean
    anomaly_strength: number
    raw_model_score: number
    note: string
  }
  findings: Finding[]
  posture: {
    score: number
    posture: string
  }
}

type AnalysisResponse = {
  case: {
    case_id: string
    filename: string
    sha256: string
  }
  analysis: {
    packet_count: number
    session_count: number
    posture: {
      score: number
      posture: string
      summary: {
        critical: number
        high: number
        medium: number
        low: number
        total: number
      }
    }
    findings: Finding[]
    sessions: Session[]
  }
}

const DEMO_CASES = {
  secure: 'CASE-20260930-EFFBC0B7',
  weak: 'CASE-20260930-CB4E17C1',
}

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [data, setData] = useState<AnalysisResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  const validateEvidenceFile = (candidate: File): boolean => {
    const extension = candidate.name
      .toLowerCase()
      .split('.')
      .pop()

    if (extension !== 'pcap' && extension !== 'pcapng') {
      setFile(null)
      setError('Only PCAP and PCAPNG files are supported.')
      return false
    }

    if (candidate.size === 0) {
      setFile(null)
      setError('The selected file is empty.')
      return false
    }

    if (candidate.size > 25 * 1024 * 1024) {
      setFile(null)
      setError('The selected file exceeds the 25 MB upload limit.')
      return false
    }

    setError('')
    return true
  }
  const [selectedPacket, setSelectedPacket] = useState<number | null>(null)

  const analyzeCase = async (caseId: string) => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`/api/analysis/${caseId}`, {
        method: 'POST',
      })

      if (!response.ok) {
        throw new Error(`Analysis failed (${response.status})`)
      }

      const result = await response.json()
      setData(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  const handleUpload = async () => {
    if (!file) return

    setLoading(true)
    setError('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const uploadResponse = await fetch('/api/evidence/upload', {
        method: 'POST',
        body: formData,
      })

      if (!uploadResponse.ok) {
        throw new Error(`Upload failed (${uploadResponse.status})`)
      }

      const uploaded = await uploadResponse.json()
      const caseId =
        uploaded?.case?.case_id ??
        uploaded?.case_id

      if (!caseId) {
        throw new Error('Upload succeeded but no case ID was returned')
      }

      await analyzeCase(caseId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed')
      setLoading(false)
    }
  }

  const exportPdf = async () => {
    if (!data) return

    try {
      const response = await fetch(
        `/api/reports/${data.case.case_id}/pdf`
      )

      if (!response.ok) {
        throw new Error(`PDF export failed (${response.status})`)
      }

      const contentType = response.headers.get('content-type') || ''

      if (!contentType.toLowerCase().includes('application/pdf')) {
        throw new Error('The report server returned an unexpected file type.')
      }

      const blob = await response.blob()
      const url = URL.createObjectURL(blob)

      const link = document.createElement("a")
      link.href = url
      link.download = `${data.case.case_id}-security-assessment.pdf`

      document.body.appendChild(link)
      link.click()
      link.remove()

      URL.revokeObjectURL(url)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "PDF export failed"
      )
    }
  }

  const exportJson = () => {
    if (!data) return

    const blob = new Blob(
      [JSON.stringify(data, null, 2)],
      { type: 'application/json' },
    )

    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${data.case.case_id}-analysis.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  const session = data?.analysis.sessions?.[0]
  const posture = data?.analysis.posture
  const score = posture?.score ?? 0
  const isSecure = score >= 80 && posture?.posture === 'SECURE'
  const ml = session?.ml
  const certificate = session?.tls?.certificate

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>
          <div>
            <div className="brand-name">SecureMailScope</div>
            <div className="brand-subtitle">
              AI-Assisted Cryptographic Security Posture Assessment
            </div>
          </div>
        </div>

        <div className="header-status">
          <span className="status-dot" />
          Offline Analysis Engine
        </div>
      </header>

      <main className="container">
        <section className="hero">
          <div>
            <div className="eyebrow">
              <Activity size={15} />
              SMTP � STARTTLS � TLS � X.509
            </div>
            <h1>Cryptographic Security Posture</h1>
            <p>
              Analyze captured mail traffic, reconstruct security state,
              identify cryptographic weaknesses, and trace findings back to
              packet evidence.
            </p>
          </div>

          <div className="hero-actions">
            <button
              className="demo-btn secure-demo"
              onClick={() => analyzeCase(DEMO_CASES.secure)}
            >
              <CircleCheck size={17} />
              Secure Demo
            </button>

            <button
              className="demo-btn weak-demo"
              onClick={() => analyzeCase(DEMO_CASES.weak)}
            >
              <ShieldAlert size={17} />
              Risk Demo
            </button>
          </div>
        </section>

        <section className="upload-card">
          <div
            className={`drop-zone ${dragging ? 'dragging' : ''}`}
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              const dropped = e.dataTransfer.files?.[0]
              if (dropped) validateEvidenceFile(dropped)
            }}
          >
            <div className="upload-icon">
              <Upload size={25} />
            </div>

            <h2>Analyze Evidence</h2>

            <p>
              Drop a PCAP or PCAPNG file here, or select evidence from your
              workstation.
            </p>

            <label className="choose-file">
              <input
                type="file"
                accept=".pcap,.pcapng"
                onChange={(e) => {
                const selected = e.target.files?.[0]

                if (selected) {
                  validateEvidenceFile(selected)
                } else {
                  setFile(null)
                  setError('')
                }
              }}
              />
              Choose PCAP
            </label>

            {file && (
              <div className="selected-file">
                <Database size={16} />
                <span>{file.name}</span>
                <span>{(file.size / 1024).toFixed(1)} KB</span>
              </div>
            )}

            <button
              className="analyze-btn"
              disabled={!file || loading}
              onClick={handleUpload}
            >
              {loading ? 'Analyzing Evidence�' : 'Run Security Analysis'}
              {!loading && <ChevronRight size={18} />}
            </button>
          </div>
        </section>

        {error && (
          <div className="error-banner">
            <AlertTriangle size={18} />
            {error}
          </div>
        )}

        {data && session && posture && (
          <>
            <section className="score-grid">
              <div className={`score-card ${isSecure ? 'secure' : 'critical'}`}>
                <div className="score-card-top">
                  <span>SECURITY POSTURE</span>
                  {isSecure ? (
                    <ShieldCheck size={24} />
                  ) : (
                    <ShieldAlert size={24} />
                  )}
                </div>

                <div className="score">{score}</div>
                <div className="score-denominator">/ 100</div>

                <div className="posture-label">{posture.posture}</div>

                <div className="score-track">
                  <div
                    className="score-fill"
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>

              <StatCard
                icon={<FileSearch size={21} />}
                label="Evidence"
                value={String(data.analysis.packet_count)}
                sub="Packets analyzed"
              />

              <StatCard
                icon={<Server size={21} />}
                label="Sessions"
                value={String(data.analysis.session_count)}
                sub={`${session.protocol} traffic`}
              />

              <StatCard
                icon={<AlertTriangle size={21} />}
                label="Findings"
                value={String(posture.summary.total)}
                sub={`${posture.summary.critical} critical � ${posture.summary.high} high`}
              />
            </section>

            <section className="section-grid">
              <div className="panel">
                <div className="panel-title">
                  <LockKeyhole size={19} />
                  STARTTLS State
                </div>

                <div className="timeline">
                  <TimelineStep
                    label="Advertised"
                    ok={session.starttls.advertised}
                    packets={session.starttls.evidence.advertised_packets}
                  />
                  <TimelineStep
                    label="Requested"
                    ok={session.starttls.requested}
                    packets={session.starttls.evidence.requested_packets}
                  />
                  <TimelineStep
                    label="Accepted"
                    ok={session.starttls.accepted}
                    packets={session.starttls.evidence.accepted_packets}
                  />
                  <TimelineStep
                    label="TLS Upgrade"
                    ok={session.starttls.upgraded}
                    packets={session.starttls.evidence.tls_packets}
                  />
                </div>

                <div className="state-badge">
                  {session.starttls.final_state}
                </div>
              </div>

              <div className="panel">
                <div className="panel-title">
                  <ShieldCheck size={19} />
                  TLS / Cryptography
                </div>

                <InfoRows
                  rows={[
                    ['Negotiated Version', session.tls.negotiated_version ?? 'Not detected'],
                    ['Cipher Suite', session.tls.selected_cipher_suite ?? 'Not detected'],
                    ['Key Exchange', session.tls.key_exchange ?? 'Not detected'],
                    ['Forward Secrecy', session.tls.forward_secrecy ? 'Enabled' : 'Unavailable'],
                    ['Server Name', session.tls.server_name ?? 'Not detected'],
                  ]}
                />
              </div>
            </section>

            <section className="section-grid">
              <div className="panel">
                <div className="panel-title">
                  <Fingerprint size={19} />
                  X.509 Certificate
                </div>

                {certificate ? (
                  <>
                    <div className="cert-state">
                      {certificate.expired ? (
                        <>
                          <CircleX size={19} />
                          Certificate Expired / Invalid
                        </>
                      ) : (
                        <>
                          <CircleCheck size={19} />
                          Certificate Valid
                        </>
                      )}
                    </div>

                    <InfoRows
                      rows={[
                        ['Subject', certificate.subject],
                        ['Issuer', certificate.issuer],
                        ['Common Name', certificate.common_name],
                        ['SAN', certificate.san_dns_names.join(', ')],
                        ['SHA-256', certificate.sha256_fingerprint],
                      ]}
                    />
                  </>
                ) : (
                  <div className="empty-state">No X.509 certificate observed.</div>
                )}
              </div>

              <div className="panel ai-panel">
                <div className="panel-title">
                  <BrainCircuit size={19} />
                  AI Anomaly Assessment
                </div>

                {ml ? (
                  <>
                    <div className={`ai-result ${ml.is_anomaly ? 'anomaly' : 'normal'}`}>
                      {ml.is_anomaly ? (
                        <ShieldAlert size={24} />
                      ) : (
                        <CircleCheck size={24} />
                      )}

                      <div>
                        <strong>{ml.classification}</strong>
                        <span>Isolation Forest</span>
                      </div>
                    </div>

                    <div className="metric">
                      <span>Anomaly Strength</span>
                      <strong>{ml.anomaly_strength.toFixed(3)}</strong>
                    </div>

                    <div className="metric">
                      <span>Model Score</span>
                      <strong>{ml.raw_model_score.toFixed(5)}</strong>
                    </div>

                    <p className="ai-note">{ml.note}</p>
                  </>
                ) : (
                  <div className="empty-state">No ML result available.</div>
                )}
              </div>
            </section>

            <section className="panel findings-panel">
              <div className="panel-heading">
                <div>
                  <div className="panel-title">
                    <AlertTriangle size={19} />
                    Security Findings
                  </div>
                  <div className="panel-subtitle">
                    Rule-backed findings with packet-level evidence
                  </div>
                </div>

                <button className="export-btn" onClick={exportJson}>
                  Export JSON
                </button>

                <button className="export-btn pdf-btn" onClick={exportPdf}>
                  Export PDF
                </button>
              </div>

              {data.analysis.findings.length === 0 ? (
                <div className="secure-empty">
                  <CircleCheck size={30} />
                  <strong>No security findings detected</strong>
                  <span>
                    The observed session satisfied the configured prototype
                    security rules.
                  </span>
                </div>
              ) : (
                <div className="findings-list">
                  {data.analysis.findings.map((finding) => (
                    <div className="finding" key={finding.id}>
                      <div className={`severity ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </div>

                      <div className="finding-main">
                        <div className="finding-title">
                          {finding.title}
                          <span>{finding.id}</span>
                        </div>

                        <p>{finding.description}</p>

                        <div className="remediation">
                          <strong>Remediation:</strong> {finding.remediation}
                        </div>

                        <div className="evidence-packets">
                          <span>Evidence packets</span>
                          {finding.evidence_packets.map((packet) => (
                            <b key={packet}>#{packet}</b>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="panel evidence-panel">
              <div className="panel-heading">
                <div>
                  <div className="panel-title">
                    <FileSearch size={19} />
                    Evidence Inspector
                  </div>
                  <div className="panel-subtitle">
                    Trace security findings back to observed packet evidence
                  </div>
                </div>
              </div>

              <div className="packet-strip">
                {session.packet_numbers.map((packet) => (
                  <button
                    key={packet}
                    className={`packet-chip ${selectedPacket === packet ? 'selected' : ''}`}
                    onClick={() => setSelectedPacket(packet)}
                  >
                    #{packet}
                  </button>
                ))}
              </div>

              {selectedPacket !== null && (
                <div className="evidence-detail">
                  <div className="evidence-detail-header">
                    <div>
                      <span className="evidence-label">SELECTED PACKET</span>
                      <h3>Packet #{selectedPacket}</h3>
                    </div>

                    <div className="evidence-type">
                      TLS / Security Evidence
                    </div>
                  </div>

                  <div className="evidence-columns">
                    <div>
                      <span className="evidence-label">LINKED FINDINGS</span>

                      <div className="linked-findings">
                        {data.analysis.findings
                          .filter((finding) =>
                            finding.evidence_packets.includes(selectedPacket)
                          )
                          .map((finding) => (
                            <div className="linked-finding" key={finding.id}>
                              <span
                                className={`mini-severity ${finding.severity.toLowerCase()}`}
                              >
                                {finding.severity}
                              </span>

                              <div>
                                <strong>{finding.title}</strong>
                                <span>{finding.id}</span>
                              </div>
                            </div>
                          ))}

                        {data.analysis.findings.filter((finding) =>
                          finding.evidence_packets.includes(selectedPacket)
                        ).length === 0 && (
                          <div className="no-linked">
                            No rule finding is linked to this packet.
                          </div>
                        )}
                      </div>
                    </div>

                    <div>
                      <span className="evidence-label">OBSERVED SECURITY FACTS</span>

                      <div className="evidence-facts">
                        <div>
                          <span>TLS Version</span>
                          <strong>
                            {session.tls.negotiated_version ?? 'Not detected'}
                          </strong>
                        </div>

                        <div>
                          <span>Cipher Suite</span>
                          <strong>
                            {session.tls.selected_cipher_suite ?? 'Not detected'}
                          </strong>
                        </div>

                        <div>
                          <span>Key Exchange</span>
                          <strong>
                            {session.tls.key_exchange ?? 'Not detected'}
                          </strong>
                        </div>

                        <div>
                          <span>Forward Secrecy</span>
                          <strong>
                            {session.tls.forward_secrecy
                              ? 'Enabled'
                              : 'Unavailable'}
                          </strong>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {selectedPacket === null && (
                <div className="evidence-placeholder">
                  <FileSearch size={22} />
                  <strong>Select a packet to inspect evidence</strong>
                  <span>
                    Evidence links connect observed packets with the security
                    findings generated by the analysis engine.
                  </span>
                </div>
              )}
            </section>
            <section className="case-footer">
              <div>
                <span>CASE ID</span>
                <strong>{data.case.case_id}</strong>
              </div>

              <div>
                <span>FILE</span>
                <strong>{data.case.filename}</strong>
              </div>

              <div>
                <span>SHA-256</span>
                <strong>{data.case.sha256}</strong>
              </div>
            </section>
          </>
        )}
      </main>

      <footer>
        SecureMailScope � Passive PCAP Analysis � Explainable Evidence
      </footer>
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  sub,
}: {
  icon: React.ReactNode
  label: string
  value: string
  sub: string
}) {
  return (
    <div className="stat-card">
      <div className="stat-icon">{icon}</div>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{sub}</small>
    </div>
  )
}

function TimelineStep({
  label,
  ok,
  packets,
}: {
  label: string
  ok: boolean
  packets: number[]
}) {
  return (
    <div className={`timeline-step ${ok ? 'complete' : 'failed'}`}>
      <div className="timeline-icon">
        {ok ? <CircleCheck size={17} /> : <CircleX size={17} />}
      </div>
      <div>
        <strong>{label}</strong>
        <span>
          {ok ? `Packet ${packets.join(', ')}` : 'Not observed'}
        </span>
      </div>
    </div>
  )
}

function InfoRows({ rows }: { rows: string[][] }) {
  return (
    <div className="info-rows">
      {rows.map(([label, value]) => (
        <div className="info-row" key={label}>
          <span>{label}</span>
          <strong title={value}>{value}</strong>
        </div>
      ))}
    </div>
  )
}

export default App
