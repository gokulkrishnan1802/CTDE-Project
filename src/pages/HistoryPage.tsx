import { useState, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore } from '../lib/storage';
import { generatePDFReport } from '../services/reportService';
import type { Investigation, RiskLevel, EvidenceType } from '../types';
import { FolderSearch, Plus, Search, ShieldCheck, AlertTriangle, ShieldAlert, Eye, Globe, Mail, Smartphone, QrCode, Send, FileDown, Clock, ArrowLeft, Activity, Bot, Lightbulb } from 'lucide-react';

interface Props {
  refreshKey: number;
  onStartNew: () => void;
}

const EVIDENCE_ICONS: Record<EvidenceType, typeof Globe> = {
  url: Globe, email: Mail, apk: Smartphone, qr: QrCode, sender: Send,
};

export default function HistoryPage({ refreshKey, onStartNew }: Props) {
  const { user } = useAuth();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Investigation | null>(null);
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [evidenceFilter, setEvidenceFilter] = useState<EvidenceType | 'all'>('all');
  const [dateFilter, setDateFilter] = useState('all');
  const investigations = useMemo<Investigation[]>(
    () => (user ? investigationStore.getByUser(user.id) : []),
    [user, refreshKey],
  );

  const filtered = useMemo(() => {
    let result = investigations.filter(i =>
      i.caseName.toLowerCase().includes(query.toLowerCase()) ||
      i.evidenceValue.toLowerCase().includes(query.toLowerCase()) ||
      i.caseId.toLowerCase().includes(query.toLowerCase()),
    );
    if (riskFilter !== 'all') result = result.filter(i => i.riskLevel === riskFilter);
    if (evidenceFilter !== 'all') result = result.filter(i => i.evidenceType === evidenceFilter);
    if (dateFilter !== 'all') {
      const now = Date.now();
      const ranges: Record<string, number> = { '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
      const cutoff = now - (ranges[dateFilter] || 0);
      result = result.filter(i => new Date(i.createdAt).getTime() >= cutoff);
    }
    return result.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [investigations, query, riskFilter, evidenceFilter, dateFilter]);

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-100">Investigation History</h2>
          <p className="text-sm text-gray-500 mt-1">All your completed investigations</p>
        </div>
        <button
          onClick={onStartNew}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 text-sm font-medium rounded-lg transition-all"
        >
          <Plus className="w-4 h-4" /> Start New Investigation
        </button>
      </div>

      {investigations.length > 0 && (
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              className="w-full bg-[#0f1620] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
              placeholder="Search by case name, ID, or evidence..."
            />
          </div>
          <div className="flex gap-2">
            <select value={riskFilter} onChange={e => setRiskFilter(e.target.value as RiskLevel | 'all')} className="bg-[#0f1620] border border-gray-800 rounded-lg px-3 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-cyan-500/50 transition-all">
              <option value="all">All Risks</option>
              <option value="Safe">Safe</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Dangerous">Dangerous</option>
            </select>
            <select value={evidenceFilter} onChange={e => setEvidenceFilter(e.target.value as EvidenceType | 'all')} className="bg-[#0f1620] border border-gray-800 rounded-lg px-3 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-cyan-500/50 transition-all">
              <option value="all">All Types</option>
              <option value="url">Website</option>
              <option value="email">Email</option>
              <option value="apk">APK</option>
              <option value="qr">QR Code</option>
              <option value="sender">Sender</option>
            </select>
            <select value={dateFilter} onChange={e => setDateFilter(e.target.value)} className="bg-[#0f1620] border border-gray-800 rounded-lg px-3 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-cyan-500/50 transition-all">
              <option value="all">All Dates</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </select>
          </div>
        </div>
      )}

      {selected ? (
        <InvestigationDetails inv={selected} onBack={() => setSelected(null)} onPDF={() => generatePDFReport(selected)} />
      ) : (
        <>
          {investigations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <div className="w-16 h-16 rounded-2xl bg-gray-800/30 border border-gray-800 flex items-center justify-center mb-4">
                <FolderSearch className="w-8 h-8 text-gray-700" />
              </div>
              <p className="text-lg font-medium text-gray-500">No investigations found</p>
              <p className="text-sm text-gray-700 mt-1">Start your first investigation to see it here</p>
              <button
                onClick={onStartNew}
                className="mt-6 flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 text-sm font-medium rounded-lg transition-all"
              >
                <Plus className="w-4 h-4" /> Start New Investigation
              </button>
            </div>
          ) : filtered.length === 0 ? (
            <p className="text-sm text-gray-600 text-center py-12">No results match your search.</p>
          ) : (
            <div className="space-y-3">
              {filtered.map(inv => {
                const Icon = EVIDENCE_ICONS[inv.evidenceType];
                return (
                  <div
                    key={inv.id}
                    className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-5 card-hover group cursor-pointer"
                    onClick={() => setSelected(inv)}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3 min-w-0 flex-1">
                        <div className="w-10 h-10 rounded-xl bg-gray-800/50 border border-gray-800 flex items-center justify-center flex-shrink-0">
                          <Icon className="w-5 h-5 text-gray-500" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <h3 className="text-sm font-semibold text-gray-200 truncate">{inv.caseName}</h3>
                            <RiskBadge level={inv.riskLevel} />
                          </div>
                          <p className="text-xs font-mono text-cyan-500/70 mb-1">{inv.caseId}</p>
                          {inv.caseDescription && <p className="text-xs text-gray-600 mb-2 line-clamp-1">{inv.caseDescription}</p>}
                          <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-gray-600">
                            <span className="uppercase">{inv.evidenceType}</span>
                            <span className="truncate max-w-xs">{inv.evidenceValue}</span>
                            <span>Score: <span className="text-gray-400">{inv.trustScore}/100</span></span>
                            <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{new Date(inv.createdAt).toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <button
                          onClick={(e) => { e.stopPropagation(); setSelected(inv); }}
                          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#0a0e14] border border-gray-800 hover:border-cyan-500/30 text-gray-500 hover:text-cyan-400 transition-all text-xs font-medium"
                        >
                          <Eye className="w-3.5 h-3.5" /> View Details
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}

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


function InvestigationDetails({ inv, onBack, onPDF }: { inv: Investigation; onBack: () => void; onPDF: () => void }) {
  const Icon = EVIDENCE_ICONS[inv.evidenceType];
  const riskColor = inv.riskLevel === 'Safe' ? 'emerald' : inv.riskLevel === 'Suspicious' ? 'yellow' : 'red';
  const scoreColor = inv.trustScore >= 70 ? 'text-emerald-400' : inv.trustScore >= 40 ? 'text-yellow-400' : 'text-red-400';

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <button onClick={onBack} className="p-2 rounded-lg bg-[#0f1620] border border-gray-800 hover:border-cyan-500/30 text-gray-400 hover:text-cyan-400 transition-all">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h2 className="text-xl font-bold text-gray-100">{inv.caseName}</h2>
            <p className="text-xs text-gray-600 font-mono">{inv.caseId}</p>
          </div>
        </div>
        <button onClick={onPDF} className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 hover:border-emerald-500/50 text-emerald-400 text-sm font-medium rounded-lg transition-all">
          <FileDown className="w-4 h-4" /> Download PDF Report
        </button>
      </div>

      {inv.caseDescription && (
        <p className="text-sm text-gray-500 bg-[#0f1620] border border-gray-800/60 rounded-xl p-4">{inv.caseDescription}</p>
      )}

      {/* Metadata grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <MetaCard label="Evidence Type" value={inv.evidenceType.toUpperCase()} icon={Icon} />
        <MetaCard label="Trust Score" value={`${inv.trustScore}/100`} valueClass={scoreColor} />
        <MetaCard label="Risk Level" value={inv.riskLevel} valueClass={`text-${riskColor}-400`} />
        <MetaCard label="Investigator" value={inv.investigator} />
        <MetaCard label="AI Confidence" value={`${inv.aiConfidence}%`} />
        <MetaCard label="Created" value={new Date(inv.createdAt).toLocaleDateString()} />
      </div>

      {/* Evidence Collected */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" /> Evidence Collected
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <MetaField label="Original URL" value={inv.evidencePanel.originalUrl} />
          <MetaField label="Resolved URL" value={inv.evidencePanel.resolvedUrl} />
          <MetaField label="IP Address" value={inv.evidencePanel.ipAddress} />
          <MetaField label="Hosting Provider" value={inv.evidencePanel.hostingProvider} />
          <MetaField label="Country" value={inv.evidencePanel.country} />
          <MetaField label="Registrar" value={inv.evidencePanel.registrar} />
          <MetaField label="SSL Status" value={inv.evidencePanel.sslStatus} />
          <MetaField label="WHOIS Status" value={inv.evidencePanel.whoisStatus} />
          <MetaField label="SHA256 Hash" value={inv.evidencePanel.sha256Hash} />
        </div>
      </div>

      {/* Verification Results */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" /> Verification Results
        </h3>
        <div className="space-y-3">
          <DetailRow label="Identity Verification" value={inv.analysis.identityVerification} />
          <DetailRow label="Domain Verification" value={inv.analysis.domainVerification} />
          <DetailRow label="Certificate Validation" value={inv.analysis.certificateValidation} />
          <DetailRow label="WHOIS Information" value={inv.analysis.whoisInfo} />
          <DetailRow label="Brand Impersonation" value={inv.analysis.brandImpersonation} />
          <DetailRow label="URL Analysis" value={inv.analysis.urlAnalysis} />
          <DetailRow label="Reputation Analysis" value={inv.analysis.reputationAnalysis} />
          {inv.analysis.apkPermissionAnalysis && <DetailRow label="APK Permissions" value={inv.analysis.apkPermissionAnalysis} />}
          {inv.analysis.senderVerification && <DetailRow label="Sender Verification" value={inv.analysis.senderVerification} />}
          {inv.analysis.qrVerification && <DetailRow label="QR Verification" value={inv.analysis.qrVerification} />}
          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">MITRE ATT&CK Mapping</p>
            <div className="flex flex-wrap gap-2">
              {inv.analysis.mitreMapping.map((m, i) => (
                <span key={i} className="text-xs font-mono px-2.5 py-1 bg-[#0a0e14] border border-gray-800 rounded text-gray-400">{m}</span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Trust Score */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" /> Digital Trust Score
        </h3>
        <div className="flex items-center gap-6">
          <div className={`text-5xl font-bold ${scoreColor}`}>{inv.trustScore}</div>
          <div className="flex-1">
            <div className="h-2 bg-[#0a0e14] rounded-full overflow-hidden">
              <div className={`h-full rounded-full transition-all duration-700`} style={{ width: `${inv.trustScore}%`, background: inv.trustScore >= 70 ? '#00ff9d' : inv.trustScore >= 40 ? '#ffb800' : '#ff3b5c' }} />
            </div>
            <p className="text-xs text-gray-500 mt-2">{inv.analysis.reasonBehindDecision}</p>
          </div>
        </div>
      </div>

      {/* AI Summary */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Bot className="w-4 h-4 text-cyan-400" /> AI Cybersecurity Analysis
        </h3>
        <div className="text-sm text-gray-400 whitespace-pre-line leading-relaxed">{inv.analysis.aiSummary}</div>
      </div>

      {/* Recommendations */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-cyan-400" /> Recommendations
        </h3>
        <ol className="space-y-2">
          {inv.analysis.recommendations.map((r, i) => (
            <li key={i} className="flex items-start gap-2.5 text-sm text-gray-400">
              <span className="text-cyan-400 font-mono text-xs mt-0.5">{i + 1}.</span>
              <span>{r}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Timeline */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" /> Investigation Timeline
        </h3>
        <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-gray-800">
          {inv.timeline.map((event, i) => (
            <div key={i} className="relative">
              <span className="absolute -left-4 top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-cyan-400/20" />
              <p className="text-sm text-gray-300">{event.label}</p>
              <p className="text-xs text-gray-600 font-mono mt-0.5">{new Date(event.timestamp).toLocaleTimeString()}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function MetaCard({ label, value, icon: Icon, valueClass }: { label: string; value: string; icon?: typeof Globe; valueClass?: string }) {
  return (
    <div className="bg-[#0f1620] border border-gray-800/60 rounded-xl p-4">
      <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-1.5">{label}</p>
      <div className="flex items-center gap-2">
        {Icon && <Icon className="w-4 h-4 text-gray-500" />}
        <p className={`text-sm font-semibold ${valueClass || 'text-gray-200'}`}>{value}</p>
      </div>
    </div>
  );
}

function MetaField({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#0a0e14] border border-gray-800/50 rounded-lg px-3 py-2">
      <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider">{label}</p>
      <p className="text-xs text-gray-300 font-mono mt-0.5 truncate">{value || '—'}</p>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-3 py-2 border-b border-gray-800/40 last:border-0">
      <p className="text-xs font-mono text-gray-500 uppercase tracking-wider w-48 flex-shrink-0">{label}</p>
      <p className="text-sm text-gray-300 flex-1">{value}</p>
    </div>
  );
}
