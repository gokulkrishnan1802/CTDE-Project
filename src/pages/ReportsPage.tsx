import { useState, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore } from '../lib/storage';
import { generatePDFReport } from '../services/reportService';
import type { Investigation, RiskLevel, EvidenceType } from '../types';
import { FileText, Download, Eye, ShieldCheck, AlertTriangle, ShieldAlert, X, Globe, Mail, Smartphone, QrCode, Send, FileJson, Printer } from 'lucide-react';

interface Props {
  refreshKey: number;
}

const EVIDENCE_ICONS: Record<EvidenceType, typeof Globe> = {
  url: Globe, email: Mail, apk: Smartphone, qr: QrCode, sender: Send,
};

export default function ReportsPage({ refreshKey }: Props) {
  const { user } = useAuth();
  const [selected, setSelected] = useState<Investigation | null>(null);

  const investigations = useMemo<Investigation[]>(
    () => (user ? investigationStore.getByUser(user.id) : []),
    [user, refreshKey],
  );

  const sorted = [...investigations].sort((a, b) =>
    b.createdAt.localeCompare(a.createdAt),
  );

  const downloadPDF = (inv: Investigation) => generatePDFReport(inv);

  const exportJSON = (inv: Investigation) => {
    const blob = new Blob([JSON.stringify(inv, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${inv.caseId}_export.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const printReport = (inv: Investigation) => {
    const win = window.open('', '_blank');
    if (!win) return;

    win.document.write(`
      <html><head><title>${inv.caseId} Report</title>
      <style>
        body{font-family:monospace;padding:40px;max-width:800px;margin:auto;color:#333}
        h1{color:#0080ff}h2{color:#006699;border-bottom:1px solid #ccc;padding-bottom:4px}
        .header{background:#0a0e14;color:#00f0ff;padding:20px;border-radius:8px;margin-bottom:20px}
        .field{margin:4px 0}.label{color:#666;font-size:11px;text-transform:uppercase}
        .section{margin:16px 0;padding:12px;border:1px solid #eee;border-radius:4px}
        .footer{margin-top:40px;border-top:1px solid #ccc;padding-top:10px;font-size:10px;color:#999;text-align:center}
      </style></head><body>
      <div class="header"><h1>CyberTrust Decision Engine (CTDE)</h1><p>Digital Forensics Investigation Report</p></div>
      <h2>Case Details</h2>
      <div class="field"><span class="label">Case ID:</span> ${inv.caseId}</div>
      <div class="field"><span class="label">Investigator:</span> ${inv.investigator}</div>
      <div class="field"><span class="label">Date:</span> ${new Date(inv.createdAt).toLocaleString()}</div>
      <div class="field"><span class="label">Evidence:</span> ${inv.evidenceType.toUpperCase()} - ${inv.evidenceValue}</div>
      <div class="field"><span class="label">Trust Score:</span> ${inv.trustScore}/100 (${inv.riskLevel})</div>
      <div class="section"><h2>Evidence Summary</h2>${inv.analysis.evidenceSummary}</div>
      <div class="section"><h2>Identity Verification</h2>${inv.analysis.identityVerification}</div>
      <div class="section"><h2>Domain Verification</h2>${inv.analysis.domainVerification}</div>
      <div class="section"><h2>Certificate Validation</h2>${inv.analysis.certificateValidation}</div>
      <div class="section"><h2>WHOIS</h2>${inv.analysis.whoisInfo}</div>
      <div class="section"><h2>Brand Impersonation</h2>${inv.analysis.brandImpersonation}</div>
      <div class="section"><h2>URL Analysis</h2>${inv.analysis.urlAnalysis}</div>
      <div class="section"><h2>Reputation Analysis</h2>${inv.analysis.reputationAnalysis}</div>
      <div class="section"><h2>MITRE ATT&CK Mapping</h2><ul>${inv.analysis.mitreMapping.map(m => `<li>${m}</li>`).join('')}</ul></div>
      <div class="section"><h2>AI Explanation</h2>${inv.analysis.aiExplanation}</div>
      <div class="section"><h2>Recommendations</h2><ol>${inv.analysis.recommendations.map(r => `<li>${r}</li>`).join('')}</ol></div>
      <div class="section"><h2>Timeline</h2><ul>${inv.timeline.map(t => `<li>${new Date(t.timestamp).toLocaleTimeString()} - ${t.label}</li>`).join('')}</ul></div>
      <div class="footer">Department of Cyber Security - College Project</div>
      </body></html>`);

    win.document.close();
    win.print();
  };

  const getSimpleLabel = (level: RiskLevel) => {
    if (level === 'Safe') return 'Looks Safe';
    if (level === 'Suspicious') return 'Be Careful';
    return 'High Risk';
  };

  const getSimpleDescription = (level: RiskLevel) => {
    if (level === 'Safe') {
      return 'No major security concerns were found in this check.';
    }

    if (level === 'Suspicious') {
      return 'Some findings need your attention before you continue.';
    }

    return 'This check found signs that may indicate a security threat.';
  };

  return (
    <div className="space-y-6 animate-fadeIn">

      {/* =========================================================
          HEADER
      ========================================================= */}
      <section className="relative overflow-hidden rounded-2xl border border-cyan-500/15 bg-[#0f1620] p-6">
        <div className="absolute -right-24 -top-24 w-72 h-72 rounded-full bg-cyan-500/5 blur-3xl pointer-events-none" />

        <div className="relative flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[10px] font-mono tracking-[0.2em] text-emerald-400/70">
                YOUR CHECKS
              </span>
            </div>

            <h1 className="text-2xl lg:text-3xl font-bold text-gray-100">
              My Reports
            </h1>

            <p className="text-sm text-gray-500 mt-2 max-w-2xl">
              View the results of things you have checked with CyberVerify AI.
            </p>
          </div>
        </div>
      </section>

      {/* =========================================================
          REPORT LIST
      ========================================================= */}
      {sorted.length === 0 ? (
        <div className="rounded-2xl border border-gray-800/60 bg-[#0f1620] flex flex-col items-center justify-center py-20 text-center">
          <div className="w-16 h-16 rounded-2xl bg-gray-800/30 border border-gray-800 flex items-center justify-center mb-4">
            <FileText className="w-8 h-8 text-gray-700" />
          </div>

          <p className="text-lg font-medium text-gray-500">
            No reports yet
          </p>

          <p className="text-sm text-gray-700 mt-1">
            Your safety check results will appear here.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {sorted.map((inv) => {
            const Icon = EVIDENCE_ICONS[inv.evidenceType];

            return (
              <div
                key={inv.id}
                className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-5 card-hover"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <div className="w-9 h-9 rounded-lg bg-gray-800/50 flex items-center justify-center">
                      <Icon className="w-4 h-4 text-gray-500" />
                    </div>

                    <span className="text-xs text-gray-500">
                      {EVIDENCE_LABELS[inv.evidenceType]}
                    </span>
                  </div>

                  <RiskBadge level={inv.riskLevel} />
                </div>

                <h3 className="text-sm font-semibold text-gray-200 mb-1">
                  {getSimpleLabel(inv.riskLevel)}
                </h3>

                <p className="text-xs text-gray-500 leading-relaxed min-h-[36px]">
                  {getSimpleDescription(inv.riskLevel)}
                </p>

                <div className="mt-4 pt-3 border-t border-gray-800/60">
                  <p className="text-[9px] font-mono text-gray-700">
                    CHECKED {new Date(inv.createdAt).toLocaleDateString()}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-2 mt-4">
                  <button
                    onClick={() => setSelected(inv)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-cyan-500/5 border border-cyan-500/15 hover:border-cyan-500/30 text-gray-400 hover:text-cyan-400 text-xs font-medium rounded-lg transition-all"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    View Result
                  </button>

                  <button
                    onClick={() => downloadPDF(inv)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-[#0a0e14] border border-gray-800 hover:border-emerald-500/30 text-gray-400 hover:text-emerald-400 text-xs font-medium rounded-lg transition-all"
                  >
                    <Download className="w-3.5 h-3.5" />
                    PDF
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2 mt-2">
                  <button
                    onClick={() => exportJSON(inv)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-[#0a0e14] border border-gray-800 hover:border-yellow-500/30 text-gray-500 hover:text-yellow-400 text-[10px] rounded-lg transition-all"
                  >
                    <FileJson className="w-3.5 h-3.5" />
                    Technical Export
                  </button>

                  <button
                    onClick={() => printReport(inv)}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-[#0a0e14] border border-gray-800 hover:border-blue-500/30 text-gray-500 hover:text-blue-400 text-[10px] rounded-lg transition-all"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    Print
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* =========================================================
          RESULT / TECHNICAL DETAILS MODAL
      ========================================================= */}
      {selected && (
        <div
          className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setSelected(null)}
        >
          <div
            className="bg-[#0f1620] border border-gray-800 rounded-2xl max-w-3xl w-full max-h-[88vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >

            {/* Modal header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-gray-200">
                    Safety Check Result
                  </h3>
                  <RiskBadge level={selected.riskLevel} />
                </div>

                <p className="text-xs text-gray-600 mt-1">
                  {EVIDENCE_LABELS[selected.evidenceType]} ·{' '}
                  {new Date(selected.createdAt).toLocaleString()}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => downloadPDF(selected)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium rounded-lg hover:bg-emerald-500/20 transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  PDF
                </button>

                <button
                  onClick={() => setSelected(null)}
                  className="p-2 rounded-lg hover:bg-gray-800/50 text-gray-500"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="overflow-y-auto p-6 space-y-5">

              {/* Simple result */}
              <div className="rounded-2xl border border-cyan-500/15 bg-[#0a0e14] p-6 text-center">
                <div className="mx-auto w-14 h-14 rounded-2xl bg-gray-800/50 border border-gray-800 flex items-center justify-center">
                  {selected.riskLevel === 'Safe' ? (
                    <ShieldCheck className="w-7 h-7 text-emerald-400" />
                  ) : selected.riskLevel === 'Suspicious' ? (
                    <AlertTriangle className="w-7 h-7 text-yellow-400" />
                  ) : (
                    <ShieldAlert className="w-7 h-7 text-red-400" />
                  )}
                </div>

                <h2 className="text-xl font-bold text-gray-100 mt-4">
                  {getSimpleLabel(selected.riskLevel)}
                </h2>

                <p className="text-sm text-gray-500 mt-2 max-w-xl mx-auto leading-relaxed">
                  {getSimpleDescription(selected.riskLevel)}
                </p>

                <div className="mt-5 inline-flex items-center gap-2 px-4 py-2 rounded-full border border-gray-800 bg-[#0f1620]">
                  <span className="text-[10px] text-gray-600 uppercase tracking-wider">
                    Check Result
                  </span>
                  <span className="text-sm font-semibold text-gray-300">
                    {selected.trustScore}/100
                  </span>
                </div>
              </div>

              {/* What we found */}
              <section className="rounded-xl border border-gray-800/60 bg-[#0a0e14] p-5">
                <h3 className="text-sm font-semibold text-gray-300">
                  What we found
                </h3>

                <p className="text-sm text-gray-500 leading-relaxed mt-2">
                  {selected.analysis.evidenceSummary}
                </p>
              </section>

              {/* AI explanation */}
              {selected.analysis.aiSummary && (
                <section className="rounded-xl border border-purple-500/15 bg-purple-500/[0.03] p-5">
                  <h3 className="text-sm font-semibold text-gray-300">
                    Simple Explanation
                  </h3>

                  <p className="text-sm text-gray-500 leading-relaxed mt-2">
                    {selected.analysis.aiSummary}
                  </p>
                </section>
              )}

              {/* Recommendations */}
              <section className="rounded-xl border border-gray-800/60 bg-[#0a0e14] p-5">
                <h3 className="text-sm font-semibold text-gray-300">
                  What should you do?
                </h3>

                <ul className="mt-3 space-y-2">
                  {selected.analysis.recommendations.map((r, i) => (
                    <li
                      key={i}
                      className="text-sm text-gray-500 flex items-start gap-2"
                    >
                      <span className="text-cyan-400 shrink-0">✓</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </section>

              {/* Technical details */}
              <details className="rounded-xl border border-gray-800/60 bg-[#0a0e14]">
                <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-gray-400 hover:text-cyan-400 transition-colors">
                  Technical Details
                  <span className="block text-[10px] font-normal text-gray-700 mt-1">
                    Advanced investigation information for technical users
                  </span>
                </summary>

                <div className="px-5 pb-5 pt-2 space-y-4 border-t border-gray-800/60">

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    <ModalField label="Case ID" value={selected.caseId} />
                    <ModalField label="Evidence Type" value={selected.evidenceType.toUpperCase()} />
                    <ModalField label="Trust Score" value={`${selected.trustScore}/100`} />
                    <ModalField label="Risk Level" value={selected.riskLevel} />
                    <ModalField label="Investigator" value={selected.investigator} />
                    <ModalField label="Date" value={new Date(selected.createdAt).toLocaleString()} />
                  </div>

                  <ModalSection title="Evidence Panel">
                    <div className="grid grid-cols-2 gap-2">
                      <ModalField label="Original URL" value={selected.evidencePanel.originalUrl} />
                      <ModalField label="Resolved URL" value={selected.evidencePanel.resolvedUrl} />
                      <ModalField label="IP Address" value={selected.evidencePanel.ipAddress} />
                      <ModalField label="Hosting" value={selected.evidencePanel.hostingProvider} />
                      <ModalField label="Country" value={selected.evidencePanel.country} />
                      <ModalField label="Registrar" value={selected.evidencePanel.registrar} />
                      <ModalField label="SSL" value={selected.evidencePanel.sslStatus} />
                      <ModalField label="WHOIS" value={selected.evidencePanel.whoisStatus} />
                    </div>

                    <div className="mt-2">
                      <ModalField
                        label="SHA256 Hash"
                        value={selected.evidencePanel.sha256Hash}
                        mono
                      />
                    </div>
                  </ModalSection>

                  <ModalSection title="Evidence Summary">
                    {selected.analysis.evidenceSummary}
                  </ModalSection>

                  <ModalSection title="Identity Verification">
                    {selected.analysis.identityVerification}
                  </ModalSection>

                  <ModalSection title="Domain Verification">
                    {selected.analysis.domainVerification}
                  </ModalSection>

                  <ModalSection title="Certificate Details">
                    {selected.analysis.certificateValidation}
                  </ModalSection>

                  <ModalSection title="WHOIS Information">
                    {selected.analysis.whoisInfo}
                  </ModalSection>

                  <ModalSection title="Brand Impersonation">
                    {selected.analysis.brandImpersonation}
                  </ModalSection>

                  <ModalSection title="URL Analysis">
                    {selected.analysis.urlAnalysis}
                  </ModalSection>

                  {selected.analysis.apkPermissionAnalysis && (
                    <ModalSection title="APK Permission Analysis">
                      {selected.analysis.apkPermissionAnalysis}
                    </ModalSection>
                  )}

                  {selected.analysis.senderVerification && (
                    <ModalSection title="Sender Verification">
                      {selected.analysis.senderVerification}
                    </ModalSection>
                  )}

                  {selected.analysis.qrVerification && (
                    <ModalSection title="QR Destination Verification">
                      {selected.analysis.qrVerification}
                    </ModalSection>
                  )}

                  <ModalSection title="Reputation Analysis">
                    {selected.analysis.reputationAnalysis}
                  </ModalSection>

                  <ModalSection title="MITRE ATT&CK Mapping">
                    <div className="flex flex-wrap gap-2">
                      {selected.analysis.mitreMapping.map((m, i) => (
                        <span
                          key={i}
                          className="text-xs font-mono px-2.5 py-1 bg-[#0a0e14] border border-gray-800 rounded text-gray-400"
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                  </ModalSection>

                  <ModalSection title="AI Explanation">
                    {selected.analysis.aiExplanation}
                  </ModalSection>

                  <ModalSection title="AI Summary">
                    {selected.analysis.aiSummary}
                  </ModalSection>

                  <ModalSection title="Recommendations">
                    <ul className="space-y-1.5">
                      {selected.analysis.recommendations.map((r, i) => (
                        <li
                          key={i}
                          className="text-sm text-gray-400 flex items-start gap-2"
                        >
                          <span className="text-cyan-400 shrink-0">
                            {i + 1}.
                          </span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  </ModalSection>

                  <ModalSection title="Investigation Timeline">
                    <div className="space-y-2">
                      {selected.timeline.map((event, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 text-sm"
                        >
                          <span className="w-2 h-2 rounded-full bg-cyan-400 flex-shrink-0" />
                          <span className="text-gray-400">
                            {event.label}
                          </span>
                          <span className="text-gray-600 font-mono text-xs ml-auto">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </ModalSection>

                </div>
              </details>

            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const EVIDENCE_LABELS: Record<EvidenceType, string> = {
  url: 'Website / Link',
  email: 'Email / Message',
  apk: 'Android App',
  qr: 'QR Code',
  sender: 'Sender / SMS',
};


function RiskBadge({ level }: { level: RiskLevel }) {
  const map: Record<RiskLevel, { cls: string; icon: typeof ShieldCheck }> = {
    Safe: { cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', icon: ShieldCheck },
    Suspicious: { cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', icon: AlertTriangle },
    Dangerous: { cls: 'bg-red-500/10 text-red-400 border-red-500/30', icon: ShieldAlert },
  };
  const { cls, icon: Icon } = map[level];
  return (
    <span className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-mono ${cls}`}>
      <Icon className="w-3 h-3" /> {level}
    </span>
  );
}

function ModalField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-0.5">{label}</p>
      <p className={`text-xs text-gray-400 ${mono ? 'font-mono break-all' : ''}`}>{value}</p>
    </div>
  );
}

function ModalSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">{title}</h4>
      <div className="text-sm text-gray-400 leading-relaxed">{children}</div>
    </div>
  );
}
