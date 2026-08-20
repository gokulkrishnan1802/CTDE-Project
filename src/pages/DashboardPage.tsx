import { useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore } from '../lib/storage';
import type {
  Investigation,
  RiskLevel,
  EvidenceType,
} from '../types';
import type { PageKey } from '../components/AppLayout';

import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileText,
  FolderSearch,
  Plus,
  TrendingUp,
  Globe,
  Mail,
  Smartphone,
  QrCode,
  Send,
  Network,
  BrainCircuit,
  Target,
  Database,
  Activity,
  ArrowUpRight,
  ChevronRight,
  Lock,
  ScanSearch,
} from 'lucide-react';

interface Props {
  onNavigate: (page: PageKey) => void;
  refreshKey: number;
}

const EVIDENCE_ICONS: Record<
  EvidenceType,
  typeof Globe
> = {
  url: Globe,
  email: Mail,
  apk: Smartphone,
  qr: QrCode,
  sender: Send,
};

const EVIDENCE_LABELS: Record<EvidenceType, string> = {
  url: 'Website',
  email: 'Email',
  apk: 'APK',
  qr: 'QR Code',
  sender: 'Sender',
};

export default function DashboardPage({
  onNavigate,
  refreshKey,
}: Props) {
  const { user } = useAuth();

  const investigations = useMemo<Investigation[]>(
    () =>
      user
        ? investigationStore.getByUser(user.id)
        : [],
    [user, refreshKey],
  );

  const stats = useMemo(() => {
    const total = investigations.length;

    const safe = investigations.filter(
      (i) => i.riskLevel === 'Safe',
    ).length;

    const suspicious = investigations.filter(
      (i) => i.riskLevel === 'Suspicious',
    ).length;

    const dangerous = investigations.filter(
      (i) => i.riskLevel === 'Dangerous',
    ).length;

    const averageScore =
      total > 0
        ? Math.round(
            investigations.reduce(
              (sum, i) => sum + i.trustScore,
              0,
            ) / total,
          )
        : 0;

    return {
      total,
      safe,
      suspicious,
      dangerous,
      reports: total,
      averageScore,
    };
  }, [investigations]);

  const evidenceCounts = useMemo(() => {
    const counts: Record<EvidenceType, number> = {
      url: 0,
      email: 0,
      apk: 0,
      qr: 0,
      sender: 0,
    };

    investigations.forEach((i) => {
      counts[i.evidenceType]++;
    });

    return counts;
  }, [investigations]);

  const recent = useMemo(
    () =>
      [...investigations]
        .sort((a, b) =>
          b.createdAt.localeCompare(a.createdAt),
        )
        .slice(0, 5),
    [investigations],
  );

  const quickActions = [
    {
      key: 'verify-url' as PageKey,
      label: 'Website / URL',
      description: 'Analyze web resource',
      icon: Globe,
    },
    {
      key: 'verify-domain' as PageKey,
      label: 'Domain',
      description: 'Inspect domain identity',
      icon: Network,
    },
    {
      key: 'verify-email' as PageKey,
      label: 'Email',
      description: 'Analyze email evidence',
      icon: Mail,
    },
    {
      key: 'verify-qr' as PageKey,
      label: 'QR Code',
      description: 'Decode & investigate',
      icon: QrCode,
    },
    {
      key: 'verify-apk' as PageKey,
      label: 'APK',
      description: 'Analyze Android package',
      icon: Smartphone,
    },
  ];

  return (
    <div className="space-y-6 animate-fadeIn">

      {/* ================================================= */}
      {/* HEADER */}
      {/* ================================================= */}

      <section className="relative overflow-hidden rounded-2xl border border-cyan-500/10 bg-[#0f1620] p-6">

        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute -right-24 -top-24 w-72 h-72 rounded-full bg-cyan-500/5 blur-3xl" />
          <div className="absolute -left-20 -bottom-24 w-60 h-60 rounded-full bg-emerald-500/5 blur-3xl" />
        </div>

        <div className="relative flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">

          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />

              <span className="text-[10px] font-mono tracking-[0.2em] text-emerald-400/70">
                FORENSIC SYSTEM ONLINE
              </span>
            </div>

            <h1 className="text-2xl lg:text-3xl font-bold text-gray-100">
              Digital Trust Command Center
            </h1>

            <p className="text-sm text-gray-500 mt-2 max-w-2xl">
              Investigate digital evidence, correlate threats,
              calculate trust and generate forensic intelligence.
            </p>
          </div>

          <button
            onClick={() => onNavigate('new-investigation')}
            className="group flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/15 border border-cyan-500/30 hover:border-cyan-400/50 text-cyan-400 text-sm font-semibold transition-all"
          >
            <Plus className="w-4 h-4" />

            New Investigation

            <ArrowUpRight
              className="w-4 h-4 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
            />
          </button>

        </div>
      </section>


      {/* ================================================= */}
      {/* SYSTEM OVERVIEW */}
      {/* ================================================= */}

      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3">

        <OverviewCard
          icon={FolderSearch}
          label="Investigations"
          value={stats.total}
          description="Total cases"
          accent="cyan"
        />

        <OverviewCard
          icon={ShieldCheck}
          label="Safe"
          value={stats.safe}
          description="Low-risk findings"
          accent="emerald"
        />

        <OverviewCard
          icon={AlertTriangle}
          label="Suspicious"
          value={stats.suspicious}
          description="Requires review"
          accent="yellow"
        />

        <OverviewCard
          icon={ShieldAlert}
          label="Dangerous"
          value={stats.dangerous}
          description="High-risk findings"
          accent="red"
        />

      </section>


      {/* ================================================= */}
      {/* QUICK INVESTIGATION */}
      {/* ================================================= */}

      <section>

        <SectionHeading
          icon={ScanSearch}
          title="Quick Investigation"
          subtitle="Select an evidence source to begin analysis"
        />

        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">

          {quickActions.map((action) => {
            const Icon = action.icon;

            return (
              <button
                key={action.key}
                onClick={() =>
                  onNavigate(action.key)
                }
                className="group text-left rounded-xl border border-gray-800/70 bg-[#0f1620] hover:border-cyan-500/30 hover:bg-cyan-500/[0.03] p-4 transition-all duration-200"
              >

                <div className="flex items-center justify-between">

                  <div className="w-9 h-9 rounded-lg bg-gray-800/50 group-hover:bg-cyan-500/10 border border-gray-800 group-hover:border-cyan-500/20 flex items-center justify-center transition-all">

                    <Icon className="w-4 h-4 text-gray-500 group-hover:text-cyan-400" />

                  </div>

                  <ChevronRight className="w-4 h-4 text-gray-700 group-hover:text-cyan-500 transition-colors" />

                </div>

                <p className="text-sm font-medium text-gray-300 mt-4 group-hover:text-gray-100">
                  {action.label}
                </p>

                <p className="text-[10px] text-gray-600 mt-1">
                  {action.description}
                </p>

              </button>
            );
          })}

        </div>
      </section>


      {/* ================================================= */}
      {/* TRUST SCORE + RISK */}
      {/* ================================================= */}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        <section className="lg:col-span-2 rounded-2xl border border-gray-800/60 bg-[#0f1620] p-5">

          <SectionHeading
            icon={TrendingUp}
            title="Trust Intelligence"
            subtitle="Average trust score across investigations"
          />

          <div className="flex flex-col sm:flex-row gap-6">

            <div className="flex items-center justify-center sm:w-40">

              <TrustScore
                score={stats.averageScore}
              />

            </div>

            <div className="flex-1">

              <div className="grid grid-cols-3 gap-3 mb-5">

                <MiniMetric
                  label="Safe"
                  value={stats.safe}
                  icon={ShieldCheck}
                  accent="emerald"
                />

                <MiniMetric
                  label="Review"
                  value={stats.suspicious}
                  icon={AlertTriangle}
                  accent="yellow"
                />

                <MiniMetric
                  label="Critical"
                  value={stats.dangerous}
                  icon={ShieldAlert}
                  accent="red"
                />

              </div>

              <div className="rounded-xl bg-[#0a0e14] border border-gray-800/60 p-4">

                <div className="flex items-center justify-between mb-3">

                  <span className="text-[10px] font-mono text-gray-600 uppercase tracking-wider">
                    Risk Distribution
                  </span>

                  <span className="text-[10px] font-mono text-gray-700">
                    {stats.total} CASES
                  </span>

                </div>

                <RiskBar
                  safe={stats.safe}
                  suspicious={stats.suspicious}
                  dangerous={stats.dangerous}
                />

              </div>

            </div>

          </div>

        </section>


        {/* Security Status */}

        <section className="rounded-2xl border border-gray-800/60 bg-[#0f1620] p-5">

          <SectionHeading
            icon={ShieldCheck}
            title="Security Status"
            subtitle="Core intelligence services"
          />

          <div className="space-y-2">

            <StatusRow
              icon={Database}
              label="Evidence Engine"
              status="Operational"
            />

            <StatusRow
              icon={Network}
              label="Threat Intelligence"
              status="Operational"
            />

            <StatusRow
              icon={BrainCircuit}
              label="AI Assistant"
              status="Ready"
            />

            <StatusRow
              icon={Target}
              label="MITRE Mapping"
              status="Ready"
            />

            <StatusRow
              icon={Lock}
              label="Evidence Integrity"
              status="Protected"
            />

          </div>

        </section>

      </div>


      {/* ================================================= */}
      {/* RECENT CASES + EVIDENCE */}
      {/* ================================================= */}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Recent Cases */}

        <section className="rounded-2xl border border-gray-800/60 bg-[#0f1620] p-5">

          <div className="flex items-center justify-between mb-4">

            <SectionHeading
              icon={Activity}
              title="Recent Investigations"
              subtitle="Latest forensic cases"
            />

            <button
              onClick={() =>
                onNavigate('history')
              }
              className="text-[10px] font-mono text-gray-600 hover:text-cyan-400 transition-colors"
            >
              VIEW ALL →
            </button>

          </div>

          {recent.length > 0 ? (
            <div className="space-y-2">

              {recent.map((inv) => {

                const Icon =
                  EVIDENCE_ICONS[
                    inv.evidenceType
                  ];

                return (
                  <div
                    key={inv.id}
                    className="flex items-center justify-between gap-3 p-3 rounded-xl bg-[#0a0e14] border border-gray-800/50 hover:border-gray-700 transition-colors"
                  >

                    <div className="flex items-center gap-3 min-w-0">

                      <div className="w-9 h-9 shrink-0 rounded-lg bg-gray-800/40 border border-gray-800 flex items-center justify-center">

                        <Icon className="w-4 h-4 text-gray-500" />

                      </div>

                      <div className="min-w-0">

                        <p className="text-xs font-medium text-gray-300 truncate">
                          {inv.caseName}
                        </p>

                        <p className="text-[9px] font-mono text-gray-700 mt-1">
                          {inv.caseId}
                        </p>

                      </div>

                    </div>

                    <div className="flex items-center gap-2 shrink-0">

                      <span className="text-xs font-mono text-gray-400">
                        {inv.trustScore}
                      </span>

                      <RiskBadge
                        level={inv.riskLevel}
                      />

                    </div>

                  </div>
                );

              })}

            </div>
          ) : (
            <EmptyState
              message="No investigations yet"
              action="Start your first investigation"
              onClick={() =>
                onNavigate('new-investigation')
              }
            />
          )}

        </section>


        {/* Evidence Overview */}

        <section className="rounded-2xl border border-gray-800/60 bg-[#0f1620] p-5">

          <SectionHeading
            icon={FolderSearch}
            title="Evidence Overview"
            subtitle="Investigated evidence sources"
          />

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">

            {(Object.keys(
              evidenceCounts,
            ) as EvidenceType[]).map((type) => {

              const Icon =
                EVIDENCE_ICONS[type];

              return (
                <div
                  key={type}
                  className="rounded-xl bg-[#0a0e14] border border-gray-800/50 p-4"
                >

                  <div className="flex items-center justify-between">

                    <Icon className="w-4 h-4 text-gray-600" />

                    <span className="text-lg font-bold font-mono text-gray-300">
                      {evidenceCounts[type]}
                    </span>

                  </div>

                  <p className="text-[10px] text-gray-600 mt-3 uppercase tracking-wider">
                    {EVIDENCE_LABELS[type]}
                  </p>

                </div>
              );

            })}

          </div>

        </section>

      </div>


      {/* ================================================= */}
      {/* INTELLIGENCE SHORTCUTS */}
      {/* ================================================= */}

      <section>

        <SectionHeading
          icon={BrainCircuit}
          title="CyberTrust Intelligence"
          subtitle="Continue your investigation workflow"
        />

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">

          <IntelligenceCard
            icon={BrainCircuit}
            title="CTDE Decision Engine"
            description="Correlate evidence and determine digital trust."
            onClick={() =>
              onNavigate('ctde')
            }
          />

          <IntelligenceCard
            icon={Target}
            title="MITRE ATT&CK"
            description="Map investigation findings to threat techniques."
            onClick={() =>
              onNavigate('mitre')
            }
          />

          <IntelligenceCard
            icon={FileText}
            title="Investigation Reports"
            description="Review generated forensic investigation reports."
            onClick={() =>
              onNavigate('reports')
            }
          />

        </div>

      </section>

    </div>
  );
}


/* ========================================================= */
/* COMPONENTS */
/* ========================================================= */

function OverviewCard({
  icon: Icon,
  label,
  value,
  description,
  accent,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: number;
  description: string;
  accent: string;
}) {

  const accents: Record<string, string> = {
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    yellow: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
  };

  return (
    <div className="rounded-xl border border-gray-800/60 bg-[#0f1620] p-4 hover:border-gray-700 transition-colors">

      <div className="flex items-start justify-between">

        <div
          className={`w-8 h-8 rounded-lg border flex items-center justify-center ${accents[accent]}`}
        >
          <Icon className="w-4 h-4" />
        </div>

        <span className="text-[9px] font-mono text-gray-700">
          LIVE
        </span>

      </div>

      <p className="text-2xl font-bold text-gray-100 mt-4">
        {value}
      </p>

      <p className="text-xs text-gray-400 mt-1">
        {label}
      </p>

      <p className="text-[9px] text-gray-700 mt-1">
        {description}
      </p>

    </div>
  );
}


function SectionHeading({
  icon: Icon,
  title,
  subtitle,
}: {
  icon: typeof ShieldCheck;
  title: string;
  subtitle: string;
}) {

  return (
    <div className="flex items-start gap-2.5 mb-4">

      <Icon className="w-4 h-4 text-cyan-400 mt-0.5" />

      <div>
        <h2 className="text-sm font-semibold text-gray-300">
          {title}
        </h2>

        <p className="text-[9px] text-gray-700 mt-0.5">
          {subtitle}
        </p>
      </div>

    </div>
  );
}


function MiniMetric({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number;
  icon: typeof ShieldCheck;
  accent: string;
}) {

  const classes: Record<string, string> = {
    emerald: 'text-emerald-400',
    yellow: 'text-yellow-400',
    red: 'text-red-400',
  };

  return (
    <div className="rounded-lg bg-[#0a0e14] border border-gray-800/50 p-3">

      <Icon
        className={`w-3.5 h-3.5 ${classes[accent]}`}
      />

      <p className="text-lg font-bold text-gray-300 mt-2">
        {value}
      </p>

      <p className="text-[9px] text-gray-700 uppercase">
        {label}
      </p>

    </div>
  );
}


function TrustScore({
  score,
}: {
  score: number;
}) {

  const radius = 48;
  const circumference =
    2 * Math.PI * radius;

  const offset =
    circumference -
    (score / 100) * circumference;

  return (
    <div className="relative w-32 h-32">

      <svg
        width="128"
        height="128"
        className="-rotate-90"
      >

        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          stroke="#1f2937"
          strokeWidth="8"
        />

        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          stroke="#22d3ee"
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-700"
        />

      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">

        <span className="text-2xl font-bold text-gray-100">
          {score}
        </span>

        <span className="text-[8px] font-mono text-gray-700">
          AVG TRUST
        </span>

      </div>

    </div>
  );
}


function RiskBar({
  safe,
  suspicious,
  dangerous,
}: {
  safe: number;
  suspicious: number;
  dangerous: number;
}) {

  const total =
    safe + suspicious + dangerous;

  if (total === 0) {
    return (
      <div className="h-2 rounded-full bg-gray-800" />
    );
  }

  return (
    <div className="h-2 rounded-full bg-gray-800 overflow-hidden flex">

      {safe > 0 && (
        <div
          className="bg-emerald-400 transition-all"
          style={{
            width: `${(safe / total) * 100}%`,
          }}
        />
      )}

      {suspicious > 0 && (
        <div
          className="bg-yellow-400 transition-all"
          style={{
            width: `${(suspicious / total) * 100}%`,
          }}
        />
      )}

      {dangerous > 0 && (
        <div
          className="bg-red-400 transition-all"
          style={{
            width: `${(dangerous / total) * 100}%`,
          }}
        />
      )}

    </div>
  );
}


function StatusRow({
  icon: Icon,
  label,
  status,
}: {
  icon: typeof ShieldCheck;
  label: string;
  status: string;
}) {

  return (
    <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0e14] border border-gray-800/50">

      <div className="flex items-center gap-2.5">

        <Icon className="w-3.5 h-3.5 text-gray-600" />

        <span className="text-xs text-gray-400">
          {label}
        </span>

      </div>

      <div className="flex items-center gap-1.5">

        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />

        <span className="text-[9px] font-mono text-emerald-500/70">
          {status}
        </span>

      </div>

    </div>
  );
}


function IntelligenceCard({
  icon: Icon,
  title,
  description,
  onClick,
}: {
  icon: typeof BrainCircuit;
  title: string;
  description: string;
  onClick: () => void;
}) {

  return (
    <button
      onClick={onClick}
      className="group text-left rounded-xl border border-gray-800/60 bg-[#0f1620] hover:border-cyan-500/20 hover:bg-cyan-500/[0.02] p-4 transition-all"
    >

      <div className="flex items-center justify-between">

        <div className="w-9 h-9 rounded-lg bg-cyan-500/5 border border-cyan-500/10 flex items-center justify-center">

          <Icon className="w-4 h-4 text-cyan-500/70 group-hover:text-cyan-400" />

        </div>

        <ArrowUpRight className="w-4 h-4 text-gray-700 group-hover:text-cyan-400" />

      </div>

      <h3 className="text-sm font-medium text-gray-300 mt-4">
        {title}
      </h3>

      <p className="text-[10px] text-gray-600 mt-1 leading-relaxed">
        {description}
      </p>

    </button>
  );
}


function RiskBadge({
  level,
}: {
  level: RiskLevel;
}) {

  const map: Record<RiskLevel, string> = {
    Safe:
      'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    Suspicious:
      'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    Dangerous:
      'bg-red-500/10 text-red-400 border-red-500/30',
  };

  return (
    <span
      className={`text-[9px] px-2 py-1 rounded-full border font-mono ${map[level]}`}
    >
      {level}
    </span>
  );
}


function EmptyState({
  message,
  action,
  onClick,
}: {
  message: string;
  action: string;
  onClick: () => void;
}) {

  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">

      <div className="w-10 h-10 rounded-xl bg-gray-800/40 border border-gray-800 flex items-center justify-center">

        <FolderSearch className="w-4 h-4 text-gray-600" />

      </div>

      <p className="text-xs text-gray-600 mt-3">
        {message}
      </p>

      <button
        onClick={onClick}
        className="text-[10px] font-mono text-cyan-500/70 hover:text-cyan-400 mt-2"
      >
        {action} →
      </button>

    </div>
  );
}