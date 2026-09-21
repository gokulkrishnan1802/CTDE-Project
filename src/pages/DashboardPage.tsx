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

    return {
      total,
      safe,
      suspicious,
      dangerous,
    };
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
      label: 'Website / Link',
      description: 'Check a website or link before you trust it',
      icon: Globe,
    },
    {
      key: 'verify-email' as PageKey,
      label: 'Email / Message',
      description: 'Check a suspicious email or message',
      icon: Mail,
    },
    {
      key: 'verify-qr' as PageKey,
      label: 'QR Code',
      description: 'Find out where a QR code takes you',
      icon: QrCode,
    },
    {
      key: 'verify-apk' as PageKey,
      label: 'Android App',
      description: 'Check an Android application',
      icon: Smartphone,
    },
    {
      key: 'new-investigation' as PageKey,
      label: 'Sender / SMS',
      description: 'Check a suspicious sender or SMS',
      icon: Send,
    },
  ];

  return (
    <div className="space-y-6 animate-fadeIn">

      {/* =========================================================
          PUBLIC-FACING HERO
      ========================================================= */}
      <section className="relative overflow-hidden rounded-2xl border border-cyan-500/20 bg-[#071018] min-h-[280px] lg:min-h-[320px] group">

        <video
          className="absolute inset-0 w-full h-full object-cover scale-[1.02] transition-transform duration-[8000ms] ease-out group-hover:scale-105"
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
        >
          <source
            src="/animations/cyber-security.mp4"
            type="video/mp4"
          />
        </video>

        <div className="absolute inset-0 bg-[#050b12]/55" />
        <div className="absolute inset-0 bg-gradient-to-r from-[#050b12]/95 via-[#071018]/75 to-transparent" />
        <div className="absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-[#050b12]/85 to-transparent" />
        <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none" />

        <div className="absolute left-0 right-0 h-px bg-cyan-400/30 shadow-[0_0_12px_rgba(34,211,238,0.5)] animate-scan pointer-events-none" />

        <div className="relative z-10 flex min-h-[280px] lg:min-h-[320px] items-center px-6 py-8 lg:px-10">
          <div className="max-w-2xl">

            <div className="flex items-center gap-2 mb-4">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60 animate-ping" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
              </span>

              <span className="text-[10px] font-mono uppercase tracking-[0.25em] text-emerald-400">
                CyberVerify AI Online
              </span>
            </div>

            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-white leading-tight">
              Stay Safe
              <span className="block text-cyan-400 drop-shadow-[0_0_18px_rgba(34,211,238,0.25)]">
                Before You Trust
              </span>
            </h1>

            <p className="mt-4 text-sm lg:text-base text-gray-300/90 max-w-xl leading-relaxed">
              Check websites, messages, QR codes and Android apps
              for potential security risks before you interact with them.
            </p>

            <button
              onClick={() => onNavigate('new-investigation')}
              className="mt-6 inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/15 border border-cyan-500/30 hover:border-cyan-400/50 text-cyan-300 text-sm font-semibold transition-all"
            >
              <ScanSearch className="w-4 h-4" />
              Check Something
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="absolute top-5 right-5 hidden lg:flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-500/15 bg-black/20 backdrop-blur-sm">
          <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-[9px] font-mono tracking-wider text-cyan-400/70">
            PROTECTED
          </span>
        </div>

        <div className="absolute top-3 left-3 w-5 h-5 border-l border-t border-cyan-400/30 pointer-events-none" />
        <div className="absolute top-3 right-3 w-5 h-5 border-r border-t border-cyan-400/30 pointer-events-none" />
        <div className="absolute bottom-3 left-3 w-5 h-5 border-l border-b border-cyan-400/30 pointer-events-none" />
        <div className="absolute bottom-3 right-3 w-5 h-5 border-r border-b border-cyan-400/30 pointer-events-none" />
      </section>

      {/* =========================================================
          CHECK OPTIONS
      ========================================================= */}
      <section>
        <SectionHeading
          icon={ScanSearch}
          title="What would you like to check?"
          subtitle="Choose something you received or are unsure about"
        />

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
          {quickActions.map((action) => {
            const Icon = action.icon;

            return (
              <button
                key={action.key}
                onClick={() => onNavigate(action.key)}
                className="group text-left rounded-xl border border-gray-800/70 bg-[#0f1620] hover:border-cyan-500/30 hover:bg-cyan-500/[0.03] p-4 transition-all duration-200"
              >
                <div className="flex items-center justify-between">
                  <div className="w-10 h-10 rounded-lg bg-gray-800/50 group-hover:bg-cyan-500/10 border border-gray-800 group-hover:border-cyan-500/20 flex items-center justify-center transition-all">
                    <Icon className="w-4 h-4 text-gray-500 group-hover:text-cyan-400" />
                  </div>

                  <ChevronRight className="w-4 h-4 text-gray-700 group-hover:text-cyan-500 transition-colors" />
                </div>

                <p className="text-sm font-medium text-gray-300 mt-4 group-hover:text-gray-100">
                  {action.label}
                </p>

                <p className="text-[10px] text-gray-600 mt-1 leading-relaxed">
                  {action.description}
                </p>
              </button>
            );
          })}
        </div>
      </section>

      {/* =========================================================
          SIMPLE ACTIVITY SUMMARY
      ========================================================= */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3">

        <OverviewCard
          icon={FolderSearch}
          label="Checks"
          value={stats.total}
          description="Total checks"
          accent="cyan"
        />

        <OverviewCard
          icon={ShieldCheck}
          label="Safe"
          value={stats.safe}
          description="No major risk found"
          accent="emerald"
        />

        <OverviewCard
          icon={AlertTriangle}
          label="Be Careful"
          value={stats.suspicious}
          description="Needs your attention"
          accent="yellow"
        />

        <OverviewCard
          icon={ShieldAlert}
          label="High Risk"
          value={stats.dangerous}
          description="Potentially dangerous"
          accent="red"
        />

      </section>

      {/* =========================================================
          RECENT CHECKS
      ========================================================= */}
      <section className="rounded-2xl border border-gray-800/60 bg-[#0f1620] p-5">

        <div className="flex items-center justify-between mb-4">
          <SectionHeading
            icon={Activity}
            title="Your Recent Checks"
            subtitle="See what you checked recently"
          />

          <button
            onClick={() => onNavigate('history')}
            className="text-[10px] font-mono text-gray-600 hover:text-cyan-400 transition-colors"
          >
            VIEW ALL →
          </button>
        </div>

        {recent.length > 0 ? (
          <div className="space-y-2">
            {recent.map((inv) => {
              const Icon = EVIDENCE_ICONS[inv.evidenceType];

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
                        {EVIDENCE_LABELS[inv.evidenceType]}
                      </p>

                      <p className="text-[9px] text-gray-700 mt-1 truncate">
                        {inv.caseName}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <RiskBadge level={inv.riskLevel} />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <EmptyState
            message="You haven't checked anything yet."
            action="Start your first check"
            onClick={() => onNavigate('new-investigation')}
          />
        )}
      </section>

      {/* =========================================================
          SIMPLE HELP / AI
      ========================================================= */}
      <section className="rounded-2xl border border-purple-500/15 bg-[#0f1620] p-5 relative overflow-hidden">
        <div className="absolute -right-20 -top-20 w-56 h-56 rounded-full bg-purple-500/5 blur-3xl pointer-events-none" />

        <div className="relative flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 shrink-0 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
              <BrainCircuit className="w-4 h-4 text-purple-400" />
            </div>

            <div>
              <h2 className="text-sm font-semibold text-gray-200">
                Need help understanding a result?
              </h2>

              <p className="text-[10px] text-gray-600 mt-1 max-w-xl leading-relaxed">
                Ask CyberVerify to explain your security check in simple language.
              </p>
            </div>
          </div>

          <button
            onClick={() => onNavigate('assistant')}
            className="shrink-0 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-purple-500/20 bg-purple-500/5 hover:bg-purple-500/10 text-purple-300 text-xs font-medium transition-all"
          >
            Ask CyberVerify
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
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
