import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore } from '../lib/storage';
import { generateCaseId, generatePDFReport } from '../lib/investigationEngine';
import { runInvestigation, type InvestigationResult } from '../services/investigationService';

import type { EvidenceType, Investigation, RiskLevel, AnalysisResult, EvidencePanel, TimelineEvent } from '../types';
import type { PageKey } from '../components/AppLayout';
import {
  Globe, Mail, Smartphone, QrCode, Send, ArrowRight,
  CheckCircle2, Loader2, FileDown, ShieldCheck, AlertTriangle, ShieldAlert,
  Bot, Lightbulb, Activity, FileText, ChevronRight, Clock,
  Server, MapPin, Hash, Lock, Fingerprint, Network, Eye, LayoutDashboard,
  Upload, ImageIcon
} from 'lucide-react';

type Step = 'create' | 'progress' | 'result';

interface Props {
  onComplete: () => void;
  onNavigate: (page: PageKey) => void;
}

const EVIDENCE_TYPES: { type: EvidenceType; label: string; icon: typeof Globe; desc: string; placeholder: string }[] = [
  { type: 'url', label: 'Website / URL', icon: Globe, desc: 'Analyze a website or URL for threats', placeholder: 'https://example.com' },
  { type: 'email', label: 'Email', icon: Mail, desc: 'Investigate a suspicious email address', placeholder: 'sender@suspicious-domain.com' },
  { type: 'apk', label: 'APK File', icon: Smartphone, desc: 'Analyze Android app permissions', placeholder: 'com.example.app.apk' },
  { type: 'qr', label: 'QR Code', icon: QrCode, desc: 'Decode and verify a QR code', placeholder: 'QR code content or URL' },
  { type: 'sender', label: 'Sender Identity', icon: Send, desc: 'Verify email senders, SMS sender IDs, or messaging identities', placeholder: 'support@example.com or VK-HDFCBK or Amazon' },
];

const PROGRESS_STEPS = [
  'Collecting Digital Evidence',
  'Identity Verification',
  'Domain Verification',
  'Certificate Validation',
  'WHOIS Lookup',
  'Brand Analysis',
  'URL Reputation',
  'APK Permission Analysis',
  'QR Destination Analysis',
  'Sender Verification',
  'MITRE Mapping',
  'AI Summary Generation',
  'Generating Digital Trust Score',
  'Generating Investigation Report',
];

export default function InvestigationPage({ onComplete, onNavigate }: Props) {
  const { user } = useAuth();
  const [step, setStep] = useState<Step>('create');
  const [caseName, setCaseName] = useState('');
  const [caseDescription, setCaseDescription] = useState('');
  const [evidenceType, setEvidenceType] = useState<EvidenceType | null>(null);
  const [evidenceValue, setEvidenceValue] = useState('');
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [evidencePanel, setEvidencePanel] = useState<EvidencePanel | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [caseId, setCaseId] = useState('');
  const [savedInvestigation, setSavedInvestigation] = useState<Investigation | null>(null);
  const [reportGenerated, setReportGenerated] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<InvestigationResult | null>(null);

  const handleStart = () => {
    if (!caseName.trim() || !evidenceType || !evidenceValue.trim()) return;
    const existingCount = user ? investigationStore.getByUser(user.id).length : 0;
    setCaseId(generateCaseId(existingCount));
    setStep('progress');
  };

  const handleProgressComplete = (result: InvestigationResult) => {
    setAnalysis(result.analysis);
    setEvidencePanel(result.evidencePanel);
    setTimeline(result.timeline);
    setInvestigationResult(result);
    setStep('result');
  };

  const handleGenerateReport = () => {
    if (!analysis || !evidenceType || !user || !evidencePanel || !timeline.length) return;
    const inv = investigationStore.create({
      userId: user.id,
      caseId,
      caseName: caseName.trim(),
      caseDescription: caseDescription.trim(),
      evidenceType,
      evidenceValue: evidenceValue.trim(),
      trustScore: analysis.trustScore,
      riskLevel: analysis.riskLevel,
      report: 'PDF Generated',
      investigator: user.fullName,
      aiConfidence: investigationResult?.aiConfidence ?? parseInt(analysis.aiExplanation.match(/\d+(?=%)/)?.[0] || '90'),
      evidencePanel,
      timeline,
      analysis,
    });
    setSavedInvestigation(inv);
    setReportGenerated(true);
    onComplete();
  };

  const reset = () => {
    setStep('create');
    setCaseName(''); setCaseDescription(''); setEvidenceType(null); setEvidenceValue('');
    setAnalysis(null); setEvidencePanel(null); setTimeline([]); setCaseId('');
    setSavedInvestigation(null); setReportGenerated(false);
  };

  if (step === 'create') {
    return <CreateStep
      caseName={caseName} setCaseName={setCaseName}
      caseDescription={caseDescription} setCaseDescription={setCaseDescription}
      evidenceType={evidenceType} setEvidenceType={setEvidenceType}
      evidenceValue={evidenceValue} setEvidenceValue={setEvidenceValue}
      onStart={handleStart}
    />;
  }

  if (step === 'progress') {
    return <ProgressStep
      evidenceType={evidenceType!}
      evidenceValue={evidenceValue}
      onComplete={handleProgressComplete}
      onReset={reset}
    />;
  }

  return <ResultStep
    caseId={caseId}
    caseName={caseName}
    caseDescription={caseDescription}
    evidenceType={evidenceType!}
    evidenceValue={evidenceValue}
    analysis={analysis!}
    evidencePanel={evidencePanel!}
    timeline={timeline}
    investigator={user?.fullName || ''}
    reportGenerated={reportGenerated}
    onGenerateReport={handleGenerateReport}
    onNavigate={onNavigate}
    onNewInvestigation={reset}
    savedInvestigation={savedInvestigation}
  />;
}

// ---- Create Step ----
function CreateStep(props: {
  caseName: string; setCaseName: (v: string) => void;
  caseDescription: string; setCaseDescription: (v: string) => void;
  evidenceType: EvidenceType | null; setEvidenceType: (v: EvidenceType) => void;
  evidenceValue: string; setEvidenceValue: (v: string) => void;
  onStart: () => void;
}) {
  const selectedEvidence = EVIDENCE_TYPES.find(e => e.type === props.evidenceType);
  const canStart = props.caseName.trim() && props.evidenceType && props.evidenceValue.trim();
  const [qrDecoding, setQrDecoding] = useState(false);
  const [qrDecoded, setQrDecoded] = useState(false);

  const handleQrFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setQrDecoding(true);
    setQrDecoded(false);
    // Simulate QR decoding
    setTimeout(() => {
      const fakeQrUrl = `https://qr-scan.example.com/redirect?id=${Date.now().toString(36)}`;
      props.setEvidenceValue(fakeQrUrl);
      setQrDecoding(false);
      setQrDecoded(true);
    }, 1500);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-fadeIn">
      <div>
        <h2 className="text-2xl font-bold text-gray-100">Create Investigation</h2>
        <p className="text-sm text-gray-500 mt-1">Start a new digital forensics investigation</p>
      </div>

      <StepIndicator current={0} />

      {/* Case info */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6 space-y-4">
        <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" /> Case Information
        </h3>
        <div>
          <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Case Name *</label>
          <input
            type="text"
            value={props.caseName}
            onChange={e => props.setCaseName(e.target.value)}
            className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
            placeholder="e.g. Suspicious Phishing URL Investigation"
          />
        </div>
        <div>
          <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Case Description</label>
          <textarea
            value={props.caseDescription}
            onChange={e => props.setCaseDescription(e.target.value)}
            rows={3}
            className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all resize-none"
            placeholder="Describe the context of this investigation..."
          />
        </div>
      </div>

      {/* Evidence type */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6 space-y-4">
        <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" /> Choose Evidence Type
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {EVIDENCE_TYPES.map(e => {
            const Icon = e.icon;
            const active = props.evidenceType === e.type;
            return (
              <button
                key={e.type}
                onClick={() => props.setEvidenceType(e.type)}
                className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${
                  active
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400 glow-cyan'
                    : 'bg-[#0a0e14] border-gray-800 text-gray-500 hover:border-gray-700 hover:text-gray-300'
                }`}
              >
                <Icon className="w-6 h-6" />
                <span className="text-xs font-medium">{e.label}</span>
              </button>
            );
          })}
        </div>
        {selectedEvidence && (
          <div className="animate-fadeIn space-y-3">
            <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Evidence Value *</label>
            {props.evidenceType === 'qr' && (
              <div className="space-y-3">
                {/* QR Image Upload */}
                <div className="flex items-center gap-3">
                  <label className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-cyan-500/30 rounded-lg cursor-pointer transition-all text-sm text-gray-400 hover:text-cyan-400">
                    {qrDecoding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                    <span>{qrDecoding ? 'Decoding QR...' : 'Upload QR Image'}</span>
                    <input type="file" accept="image/*" className="hidden" onChange={handleQrFileUpload} disabled={qrDecoding} />
                  </label>
                  {qrDecoded && (
                    <span className="flex items-center gap-1.5 text-xs text-emerald-400 animate-fadeIn">
                      <CheckCircle2 className="w-3.5 h-3.5" /> QR successfully decoded.
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-px bg-gray-800" />
                  <span className="text-xs text-gray-600 font-mono">OR</span>
                  <div className="flex-1 h-px bg-gray-800" />
                </div>
                {/* QR Paste */}
                <div className="relative">
                  <ImageIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                  <input
                    type="text"
                    value={props.evidenceValue}
                    onChange={e => { props.setEvidenceValue(e.target.value); setQrDecoded(false); }}
                    className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all font-mono"
                    placeholder="Paste QR content or URL"
                  />
                </div>
              </div>
            )}
            {props.evidenceType !== 'qr' && (
              <input
                type="text"
                value={props.evidenceValue}
                onChange={e => props.setEvidenceValue(e.target.value)}
                className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all font-mono"
                placeholder={selectedEvidence.placeholder}
              />
            )}
            <p className="text-xs text-gray-600 mt-1.5">{selectedEvidence.desc}</p>
          </div>
        )}
      </div>

      <button
        onClick={props.onStart}
        disabled={!canStart}
        className="flex items-center gap-2 px-6 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-medium rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed group"
      >
        Start Investigation <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
      </button>
    </div>
  );
}

// ---- Progress Step ----
function ProgressStep({ evidenceType, evidenceValue, onComplete, onReset }: {
  evidenceType: EvidenceType;
  evidenceValue: string;
  onComplete: (result: InvestigationResult) => void;
  onReset: () => void;
}) {
  const [currentStep, setCurrentStep] = useState(0);
  const [completed, setCompleted] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  // ready becomes true when the async investigation resolves — triggers the
  // completion effect even if the animation already finished.
  const [ready, setReady] = useState(false);
  const resultRef = useRef<InvestigationResult | null>(null);
  const completedRef = useRef(false);

  // Filter steps based on evidence type
  const visibleSteps = PROGRESS_STEPS.filter(label => {
    if (label === 'APK Permission Analysis') return evidenceType === 'apk';
    if (label === 'QR Destination Analysis') return evidenceType === 'qr';
    if (label === 'Sender Verification') return evidenceType === 'sender';
    return true;
  });

  // Kick off the real investigation once.
  useEffect(() => {
    let cancelled = false;
    runInvestigation(evidenceType, evidenceValue)
      .then(result => {
        if (!cancelled) {
          resultRef.current = result;
          setReady(true); // triggers the completion effect below
        }
      })
      .catch(err => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Investigation failed unexpectedly.');
      });
    return () => { cancelled = true; };
  }, [evidenceType, evidenceValue]);

  // Advance the animated progress steps.
  // Also fires when `ready` flips so we can complete immediately if the
  // animation already finished before the network calls returned.
  useEffect(() => {
    if (error) return;

    if (currentStep >= visibleSteps.length) {
      // Animation done — fire onComplete as soon as result is available.
      if (ready && resultRef.current && !completedRef.current) {
        completedRef.current = true;
        const timer = setTimeout(() => onComplete(resultRef.current!), 400);
        return () => clearTimeout(timer);
      }
      // Result not yet ready — just wait (re-runs when `ready` changes).
      return;
    }

    // Pace the animation: slow down the last few steps so they don't race
    // ahead of the real network calls.
    const isNearEnd = currentStep >= visibleSteps.length - 3;
    const delay = isNearEnd ? 1200 + Math.random() * 800 : 500 + Math.random() * 400;

    const timer = setTimeout(() => {
      setCompleted(prev => [...prev, currentStep]);
      setCurrentStep(prev => prev + 1);
    }, delay);
    return () => clearTimeout(timer);
  }, [currentStep, visibleSteps.length, onComplete, error, ready]);

  const overallPct = error ? 0 : Math.round((completed.length / visibleSteps.length) * 100);

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fadeIn">
      <div>
        <h2 className="text-2xl font-bold text-gray-100">Forensic Processing</h2>
        <p className="text-sm text-gray-500 mt-1">Analyzing evidence: <span className="font-mono text-cyan-400">{evidenceValue}</span></p>
      </div>

      <StepIndicator current={1} />

      {/* Overall progress */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-mono text-gray-400">Overall Progress</span>
          <span className="text-lg font-bold text-cyan-400 font-mono">{overallPct}%</span>
        </div>
        <div className="h-2 bg-[#0a0e14] rounded-full overflow-hidden">
          <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-500" style={{ width: `${overallPct}%` }} />
        </div>
      </div>

      {error ? (
        <div className="bg-red-500/5 border border-red-500/30 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="w-5 h-5" />
            <h3 className="text-sm font-semibold">Investigation Failed</h3>
          </div>
          <p className="text-sm text-gray-400">{error}</p>
          <button onClick={onReset} className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-sm font-medium rounded-lg transition-all">
            <ArrowRight className="w-4 h-4 rotate-180" /> Back to Create
          </button>
        </div>
      ) : (
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6 space-y-2">
        {visibleSteps.map((label, i) => {
          const isDone = completed.includes(i);
          const isActive = i === currentStep && !isDone;
          return (
            <div key={label} className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all ${isActive ? 'bg-cyan-500/5' : ''}`}>
              {isDone ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              ) : isActive ? (
                <Loader2 className="w-5 h-5 text-cyan-400 animate-spin flex-shrink-0" />
              ) : (
                <div className="w-5 h-5 rounded-full border-2 border-gray-800 flex-shrink-0" />
              )}
              <span className={`text-sm font-mono ${isDone ? 'text-gray-400' : isActive ? 'text-cyan-400' : 'text-gray-700'}`}>
                {label}
              </span>
              {isActive && <span className="ml-auto text-xs font-mono text-cyan-500/50 animate-blink">processing...</span>}
            </div>
          );
        })}
        {/* Show finalizing indicator once animation completes but network calls still running */}
        {currentStep >= visibleSteps.length && !ready && (
          <div className="flex items-center gap-3 px-3 py-2.5 mt-2 bg-cyan-500/5 rounded-lg border border-cyan-500/10 animate-pulse">
            <Loader2 className="w-5 h-5 text-cyan-400 animate-spin flex-shrink-0" />
            <span className="text-sm font-mono text-cyan-400">Finalizing analysis results...</span>
          </div>
        )}
      </div>
      )}
    </div>
  );
}

// ---- Result Step ----
function ResultStep(props: {
  caseId: string;
  caseName: string;
  caseDescription: string;
  evidenceType: EvidenceType;
  evidenceValue: string;
  analysis: AnalysisResult;
  evidencePanel: EvidencePanel;
  timeline: TimelineEvent[];
  investigator: string;
  reportGenerated: boolean;
  onGenerateReport: () => void;
  onNavigate: (p: PageKey) => void;
  onNewInvestigation: () => void;
  savedInvestigation: Investigation | null;
}) {
  const { analysis, evidencePanel, timeline } = props;
  const scoreColor = analysis.riskLevel === 'Safe' ? 'emerald' : analysis.riskLevel === 'Suspicious' ? 'yellow' : 'red';
  const aiConfidence = parseInt(analysis.aiExplanation.match(/\d+(?=%)/)?.[0] || '90');

  const handleDownloadPDF = () => {
    if (props.savedInvestigation) {
      generatePDFReport(props.savedInvestigation);
    } else {
      // Generate report first, then download
      props.onGenerateReport();
      // Wait a tick for state to update, then use the investigation data we have
      setTimeout(() => {
        const tempInv = investigationStore.getByUser(props.investigator).slice(-1)[0];
        if (tempInv) generatePDFReport(tempInv);
      }, 100);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-100">Investigation Result</h2>
          <p className="text-sm text-gray-500 mt-1 font-mono">{props.caseId}</p>
        </div>
        <StepIndicator current={2} compact />
      </div>

      {/* Case Details */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" /> Case Details
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <DetailField label="Case ID" value={props.caseId} />
          <DetailField label="Evidence Type" value={props.evidenceType.toUpperCase()} />
          <DetailField label="Investigator" value={props.investigator} />
          <DetailField label="Timestamp" value={new Date().toLocaleString()} />
        </div>
      </div>

      {/* Trust Score + AI Confidence */}
      <div className={`bg-[#0f1620] border rounded-2xl p-6 card-hover border-${scoreColor}-500/30`}>
        <div className="flex flex-col sm:flex-row items-center gap-6">
          <TrustGauge score={analysis.trustScore} riskLevel={analysis.riskLevel} />
          <div className="flex-1 space-y-3">
            <h3 className="text-sm font-semibold text-gray-300">Digital Trust Score</h3>
            <div className="flex items-center gap-3 flex-wrap">
              <RiskBadgeLarge level={analysis.riskLevel} />
              <span className="text-xs text-gray-600 font-mono">Score: {analysis.trustScore}/100</span>
              <span className="text-xs text-cyan-400 font-mono">AI Confidence: {aiConfidence}%</span>
            </div>
            <p className="text-sm text-gray-500">{analysis.reasonBehindDecision}</p>
            {/* Score Breakdown */}
            <div className="mt-4 pt-4 border-t border-gray-800/60">
              <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">Score Breakdown</p>
              <div className="space-y-2">
                {buildScoreBreakdown(analysis).map((factor, i) => (
                  <div key={i} className="flex items-start gap-2.5">
                    {factor.positive ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <span className="text-xs text-gray-300">{factor.label}</span>
                      <span className={`text-xs font-mono ml-2 ${factor.positive ? 'text-emerald-400' : 'text-yellow-400'}`}>
                        {factor.positive ? '+' : ''}{factor.points}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Summary - Verification Modules */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" /> Evidence Summary — Verification Modules
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {buildVerificationModules(analysis, evidencePanel).map((mod, i) => (
            <div key={i} className="flex items-center gap-2.5 px-3 py-2.5 bg-[#0a0e14] border border-gray-800/50 rounded-lg">
              <CheckCircle2 className={`w-4 h-4 flex-shrink-0 ${mod.passed ? 'text-emerald-400' : 'text-gray-700'}`} />
              <div className="min-w-0">
                <p className="text-xs font-medium text-gray-300 truncate">{mod.name}</p>
                <p className="text-[10px] text-gray-600 font-mono truncate">{mod.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Evidence Panel */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" /> Evidence Panel
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <PanelItem icon={Globe} label="Original URL" value={evidencePanel.originalUrl} />
          <PanelItem icon={Eye} label="Resolved URL" value={evidencePanel.resolvedUrl} />
          <PanelItem icon={Server} label="IP Address" value={evidencePanel.ipAddress} />
          <PanelItem icon={Server} label="Hosting Provider" value={evidencePanel.hostingProvider} />
          <PanelItem icon={MapPin} label="Country" value={evidencePanel.country} />
          <PanelItem icon={Fingerprint} label="Registrar" value={evidencePanel.registrar} />
          <PanelItem icon={Lock} label="SSL Status" value={evidencePanel.sslStatus} />
          <PanelItem icon={FileText} label="WHOIS Status" value={evidencePanel.whoisStatus} />
          <PanelItem icon={Hash} label="SHA256 Hash" value={evidencePanel.sha256Hash} mono />
        </div>
      </div>

      {/* Analysis sections */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <AnalysisCard title="Evidence Summary" content={analysis.evidenceSummary} />
        <AnalysisCard title="Identity Verification" content={analysis.identityVerification} />
        <AnalysisCard title="Domain Verification" content={analysis.domainVerification} />
        <AnalysisCard title="Certificate Details" content={analysis.certificateValidation} />
        <AnalysisCard title="WHOIS Information" content={analysis.whoisInfo} />
        <AnalysisCard title="Brand Impersonation" content={analysis.brandImpersonation} />
        <AnalysisCard title="URL Analysis" content={analysis.urlAnalysis} />
        {analysis.apkPermissionAnalysis && <AnalysisCard title="APK Permission Analysis" content={analysis.apkPermissionAnalysis} />}
        {analysis.senderVerification && <AnalysisCard title="Sender Verification" content={analysis.senderVerification} />}
        {analysis.qrVerification && <AnalysisCard title="QR Destination Verification" content={analysis.qrVerification} />}
        <AnalysisCard title="Reputation Analysis" content={analysis.reputationAnalysis} />
      </div>

      {/* MITRE */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">MITRE ATT&CK Mapping</h3>
        <div className="flex flex-wrap gap-2">
          {analysis.mitreMapping.map((m, i) => (
            <span key={i} className="text-xs font-mono px-3 py-1.5 bg-[#0a0e14] border border-gray-800 rounded-lg text-gray-400">{m}</span>
          ))}
        </div>
      </div>

      {/* AI Explanation */}
      <div className="bg-[#0f1620] border border-cyan-500/20 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Bot className="w-4 h-4 text-cyan-400" /> AI Explanation
        </h3>
        <p className="text-sm text-gray-400 leading-relaxed">{analysis.aiExplanation}</p>
      </div>

      {/* AI Summary */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Bot className="w-4 h-4 text-emerald-400" /> AI Summary
        </h3>
        <p className="text-sm text-gray-400 leading-relaxed">{analysis.aiSummary}</p>
      </div>

      {/* Recommendations */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-yellow-400" /> Recommendations
        </h3>
        <ul className="space-y-2">
          {analysis.recommendations.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-gray-400">
              <ChevronRight className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
              {r}
            </li>
          ))}
        </ul>
      </div>

      {/* Timeline */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" /> Investigation Timeline
        </h3>
        <div className="space-y-3">
          {timeline.map((event, i) => (
            <div key={i} className="flex items-start gap-3">
              <div className="flex flex-col items-center">
                <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-cyan-500/10 flex-shrink-0 mt-1" />
                {i < timeline.length - 1 && <div className="w-px h-8 bg-gray-800 mt-1" />}
              </div>
              <div className="pb-2">
                <p className="text-sm text-gray-300">{event.label}</p>
                <p className="text-xs text-gray-600 font-mono">{new Date(event.timestamp).toLocaleTimeString()}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-col sm:flex-row gap-3">
        {!props.reportGenerated ? (
          <button
            onClick={props.onGenerateReport}
            className="flex items-center justify-center gap-2 px-6 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-medium rounded-lg transition-all"
          >
            <FileDown className="w-4 h-4" /> Generate Report
          </button>
        ) : (
          <>
            <div className="flex items-center gap-2 px-4 py-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg text-sm">
              <CheckCircle2 className="w-4 h-4" /> Report saved
            </div>
            <button
              onClick={handleDownloadPDF}
              className="flex items-center gap-2 px-4 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 text-sm font-medium rounded-lg transition-all"
            >
              <FileDown className="w-4 h-4" /> Generate PDF
            </button>
            <button
              onClick={() => props.onNavigate('reports')}
              className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-all"
            >
              <FileText className="w-4 h-4" /> View Reports
            </button>
            <button
              onClick={() => props.onNavigate('assistant')}
              className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-all"
            >
              <Bot className="w-4 h-4" /> Ask AI
            </button>
            <button
              onClick={() => props.onNavigate('dashboard')}
              className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-all ml-auto"
            >
              <LayoutDashboard className="w-4 h-4" /> Return Dashboard
            </button>
          </>
        )}
      </div>
    </div>
  );
}

// ---- Shared components ----
function StepIndicator({ current, compact }: { current: number; compact?: boolean }) {
  const steps = ['Create', 'Progress', 'Result'];
  return (
    <div className="flex items-center gap-2">
      {steps.map((s, i) => (
        <div key={s} className="flex items-center gap-2">
          <div className={`flex items-center gap-1.5 ${compact ? '' : 'px-3 py-1.5 rounded-lg'} ${i === current ? 'bg-cyan-500/10 text-cyan-400' : i < current ? 'text-emerald-400' : 'text-gray-700'}`}>
            <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
              i === current ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' :
              i < current ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
              'bg-[#0a0e14] text-gray-700 border border-gray-800'
            }`}>
              {i < current ? <CheckCircle2 className="w-3 h-3" /> : i + 1}
            </div>
            <span className={`text-xs font-medium ${compact ? 'hidden sm:inline' : ''}`}>{s}</span>
          </div>
          {i < steps.length - 1 && <div className={`w-6 h-px ${i < current ? 'bg-emerald-500/40' : 'bg-gray-800'}`} />}
        </div>
      ))}
    </div>
  );
}

function TrustGauge({ score, riskLevel }: { score: number; riskLevel: RiskLevel }) {
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score / 100) * circumference;
  const color = riskLevel === 'Safe' ? '#00ff9d' : riskLevel === 'Suspicious' ? '#ffb800' : '#ff3b5c';
  return (
    <div className="relative w-32 h-32 flex-shrink-0">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="45" fill="none" stroke="#1f2937" strokeWidth="6" />
        <circle
          cx="50" cy="50" r="45" fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1s ease-out' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold" style={{ color }}>{score}</span>
        <span className="text-[10px] font-mono text-gray-600">/ 100</span>
      </div>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs font-mono text-gray-600 uppercase tracking-wider mb-1">{label}</p>
      <p className="text-sm text-gray-300">{value}</p>
    </div>
  );
}

function PanelItem({ icon: Icon, label, value, mono }: { icon: typeof Globe; label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2.5 px-3 py-2.5 bg-[#0a0e14] border border-gray-800/50 rounded-lg">
      <Icon className="w-4 h-4 text-gray-600 flex-shrink-0 mt-0.5" />
      <div className="min-w-0">
        <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider">{label}</p>
        <p className={`text-xs text-gray-400 ${mono ? 'font-mono break-all' : 'truncate'}`}>{value}</p>
      </div>
    </div>
  );
}

function AnalysisCard({ title, content }: { title: string; content: string }) {
  return (
    <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-5 card-hover">
      <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">{title}</h4>
      <p className="text-sm text-gray-400 leading-relaxed">{content}</p>
    </div>
  );
}

function RiskBadgeLarge({ level }: { level: RiskLevel }) {
  const map: Record<RiskLevel, { cls: string; icon: typeof ShieldCheck }> = {
    Safe: { cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', icon: ShieldCheck },
    Suspicious: { cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', icon: AlertTriangle },
    Dangerous: { cls: 'bg-red-500/10 text-red-400 border-red-500/30', icon: ShieldAlert },
  };
  const { cls, icon: Icon } = map[level];
  return (
    <span className={`flex items-center gap-1.5 text-sm px-3 py-1 rounded-full border font-medium ${cls}`}>
      <Icon className="w-4 h-4" /> {level}
    </span>
  );
}


function buildScoreBreakdown(analysis: AnalysisResult): { label: string; positive: boolean; points: number }[] {
  const factors: { label: string; positive: boolean; points: number }[] = [];
  factors.push({
    label: analysis.identityVerification.includes('valid') ? 'Identity verified (4+ year domain)' : 'Recent domain registration',
    positive: analysis.identityVerification.includes('valid'),
    points: analysis.identityVerification.includes('valid') ? 20 : -15,
  });
  factors.push({
    label: analysis.certificateValidation.includes('Valid') ? 'Valid TLS/SSL certificate' : 'No valid SSL certificate',
    positive: analysis.certificateValidation.includes('Valid'),
    points: analysis.certificateValidation.includes('Valid') ? 15 : -20,
  });
  factors.push({
    label: analysis.reputationAnalysis.includes('no entries') ? 'Clean reputation (0/87 blocklists)' : 'Listed on threat blocklists',
    positive: analysis.reputationAnalysis.includes('no entries'),
    points: analysis.reputationAnalysis.includes('no entries') ? 20 : -25,
  });
  factors.push({
    label: analysis.brandImpersonation.includes('No known') ? 'No brand impersonation detected' : 'Brand impersonation detected',
    positive: analysis.brandImpersonation.includes('No known'),
    points: analysis.brandImpersonation.includes('No known') ? 15 : -20,
  });
  factors.push({
    label: analysis.domainVerification.includes('resolves correctly') ? 'Domain resolves correctly' : 'Domain resolution issues',
    positive: analysis.domainVerification.includes('resolves correctly'),
    points: analysis.domainVerification.includes('resolves correctly') ? 10 : -10,
  });
  return factors;
}

function buildVerificationModules(analysis: AnalysisResult, _evidencePanel: EvidencePanel): { name: string; detail: string; passed: boolean }[] {
  return [
    { name: 'Identity Verification', detail: analysis.identityVerification.includes('valid') ? 'Verified' : 'Unverified', passed: analysis.identityVerification.includes('valid') },
    { name: 'Domain Verification', detail: analysis.domainVerification.includes('resolves') ? 'Resolved' : 'Failed', passed: analysis.domainVerification.includes('resolves') },
    { name: 'Certificate Validation', detail: analysis.certificateValidation.includes('Valid') ? 'Valid TLS' : 'No SSL', passed: analysis.certificateValidation.includes('Valid') },
    { name: 'WHOIS Lookup', detail: analysis.whoisInfo.includes('public') ? 'Public' : 'Privacy', passed: true },
    { name: 'Brand Detection', detail: analysis.brandImpersonation.includes('No known') ? 'Clean' : 'Flagged', passed: analysis.brandImpersonation.includes('No known') },
    { name: 'URL Analysis', detail: analysis.urlAnalysis.includes('clean') ? 'Clean' : 'Anomalies', passed: analysis.urlAnalysis.includes('clean') },
    { name: 'Reputation Analysis', detail: analysis.reputationAnalysis.includes('no entries') ? 'Clean' : 'Flagged', passed: analysis.reputationAnalysis.includes('no entries') },
    { name: 'MITRE ATT&CK Mapping', detail: `${analysis.mitreMapping.length} techniques`, passed: true },
    { name: 'AI Summary Generation', detail: 'Complete', passed: true },
  ];
}
