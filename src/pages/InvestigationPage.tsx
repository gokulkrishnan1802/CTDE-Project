import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore } from '../lib/storage';
import { generateCaseId, generatePDFReport } from '../lib/investigationEngine';

import {
  runInvestigation,
  runEmailHeaderInvestigation,
  runQrInvestigation,
  type InvestigationResult,
} from '../services/investigationService';

import type {
  EvidenceType,
  Investigation,
  RiskLevel,
  AnalysisResult,
  EvidencePanel,
  TimelineEvent,
} from '../types';

import type { PageKey } from '../components/AppLayout';

import {
  Globe,
  Mail,
  Smartphone,
  QrCode,
  Send,
  ArrowRight,
  CheckCircle2,
  Loader2,
  FileDown,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Bot,
  Lightbulb,
  Activity,
  FileText,
  ChevronRight,
  Clock,
  Server,
  MapPin,
  Hash,
  Lock,
  Fingerprint,
  Network,
  Eye,
  LayoutDashboard,
  Upload,
  ImageIcon,
} from 'lucide-react';

type Step = 'create' | 'progress' | 'result';

interface Props {
  onComplete: () => void;
  onNavigate: (page: PageKey) => void;
}

const EVIDENCE_TYPES: {
  type: EvidenceType;
  label: string;
  icon: typeof Globe;
  desc: string;
  placeholder: string;
}[] = [
  {
    type: 'url',
    label: 'Website / URL',
    icon: Globe,
    desc: 'Analyze a website or URL for threats',
    placeholder: 'https://example.com',
  },
  {
  type: 'email',
  label: 'Email Headers',
  icon: Mail,
  desc: 'Perform forensic analysis of raw email headers',
  placeholder: 'Paste raw email headers here...',
},
  {
    type: 'apk',
    label: 'APK File',
    icon: Smartphone,
    desc: 'Analyze Android app permissions',
    placeholder: 'com.example.app.apk',
  },
  {
    type: 'qr',
    label: 'QR Code',
    icon: QrCode,
    desc: 'Decode and verify a QR code',
    placeholder: 'QR code content or URL',
  },
  {
    type: 'sender',
    label: 'Sender Identity',
    icon: Send,
    desc: 'Verify email senders, SMS sender IDs, or messaging identities',
    placeholder: 'support@example.com or VK-HDFCBK or Amazon',
  },
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

export default function InvestigationPage({
  onComplete,
  onNavigate,
}: Props) {
  const { user } = useAuth();

  const [step, setStep] = useState<Step>('create');

  const [caseName, setCaseName] = useState('');
  const [caseDescription, setCaseDescription] = useState('');

  const [evidenceType, setEvidenceType] =
    useState<EvidenceType | null>(null);

  const [evidenceValue, setEvidenceValue] = useState('');

  // REAL QR IMAGE FILE
  const [qrFile, setQrFile] = useState<File | null>(null);

  const [analysis, setAnalysis] =
    useState<AnalysisResult | null>(null);

  const [evidencePanel, setEvidencePanel] =
    useState<EvidencePanel | null>(null);

  const [timeline, setTimeline] =
    useState<TimelineEvent[]>([]);

  const [caseId, setCaseId] = useState('');

  const [savedInvestigation, setSavedInvestigation] =
    useState<Investigation | null>(null);

  const [reportGenerated, setReportGenerated] =
    useState(false);

  const [investigationResult, setInvestigationResult] =
    useState<InvestigationResult | null>(null);

  // ──────────────────────────────────────────────────────────────────────────
  // START INVESTIGATION
  // ──────────────────────────────────────────────────────────────────────────

  const handleStart = () => {
    if (!caseName.trim() || !evidenceType) {
      return;
    }

    // QR can start with either:
    // 1. an uploaded QR image
    // 2. manually entered QR content / URL
    if (
      evidenceType === 'qr' &&
      !qrFile &&
      !evidenceValue.trim()
    ) {
      return;
    }

    // All other evidence types require text input.
    if (
      evidenceType !== 'qr' &&
      !evidenceValue.trim()
    ) {
      return;
    }

    const existingCount = user
      ? investigationStore.getByUser(user.id).length
      : 0;

    setCaseId(generateCaseId(existingCount));
    setStep('progress');
  };

  // ──────────────────────────────────────────────────────────────────────────
  // HANDLE COMPLETED BACKEND INVESTIGATION
  // ──────────────────────────────────────────────────────────────────────────

const handleProgressComplete = (
  result: InvestigationResult
) => {
  setAnalysis(result.analysis);

  setEvidencePanel(
    result.evidencePanel
  );

  setTimeline(
    result.timeline
  );

  setInvestigationResult(
    result
  );

  // Save the REAL decoded QR destination.
  // This replaces the uploaded image as the
  // investigation's evidence value.
  if (
    evidenceType === 'qr' &&
    result.raw.qr?.decodedUrl
  ) {
    setEvidenceValue(
      result.raw.qr.decodedUrl
    );
  }

  setStep('result');
};

  // ──────────────────────────────────────────────────────────────────────────
  // GENERATE REPORT
  // ──────────────────────────────────────────────────────────────────────────

  const handleGenerateReport = () => {
    if (
      !analysis ||
      !evidenceType ||
      !user ||
      !evidencePanel ||
      !timeline.length
    ) {
      return;
    }

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
      aiConfidence:
        investigationResult?.aiConfidence ??
        parseInt(
          analysis.aiExplanation.match(/\d+(?=%)/)?.[0] ||
            '90'
        ),
      evidencePanel,
      timeline,
      analysis,
    });

    setSavedInvestigation(inv);
    setReportGenerated(true);
    onComplete();
  };

  // ──────────────────────────────────────────────────────────────────────────
  // RESET
  // ──────────────────────────────────────────────────────────────────────────

  const reset = () => {
    setStep('create');

    setCaseName('');
    setCaseDescription('');
    setEvidenceType(null);
    setEvidenceValue('');

    // IMPORTANT: clear uploaded QR image
    setQrFile(null);

    setAnalysis(null);
    setEvidencePanel(null);
    setTimeline([]);
    setCaseId('');

    setSavedInvestigation(null);
    setReportGenerated(false);
    setInvestigationResult(null);
  };

  // ──────────────────────────────────────────────────────────────────────────
  // RENDER STEP
  // ──────────────────────────────────────────────────────────────────────────

  if (step === 'create') {
    return (
      <CreateStep
        caseName={caseName}
        setCaseName={setCaseName}
        caseDescription={caseDescription}
        setCaseDescription={setCaseDescription}
        evidenceType={evidenceType}
        setEvidenceType={(type) => {
          setEvidenceType(type);

          // Clear previous QR state when switching evidence type.
          if (type !== 'qr') {
            setQrFile(null);
          }

          setEvidenceValue('');
        }}
        evidenceValue={evidenceValue}
        setEvidenceValue={setEvidenceValue}
        qrFile={qrFile}
        setQrFile={setQrFile}
        onStart={handleStart}
      />
    );
  }

  if (step === 'progress') {
    return (
      <ProgressStep
        evidenceType={evidenceType!}
        evidenceValue={evidenceValue}
        qrFile={qrFile}
        onComplete={handleProgressComplete}
        onReset={reset}
      />
    );
  }

  return (
    <ResultStep
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
    />
  );
}


// ══════════════════════════════════════════════════════════════════════════════
// CREATE STEP
// ══════════════════════════════════════════════════════════════════════════════

function CreateStep(props: {
  caseName: string;
  setCaseName: (v: string) => void;

  caseDescription: string;
  setCaseDescription: (v: string) => void;

  evidenceType: EvidenceType | null;
  setEvidenceType: (v: EvidenceType) => void;

  evidenceValue: string;
  setEvidenceValue: (v: string) => void;

  qrFile: File | null;
  setQrFile: (file: File | null) => void;

  onStart: () => void;
}) {
  const selectedEvidence = EVIDENCE_TYPES.find(
    e => e.type === props.evidenceType
  );

  const [qrDecoding] =
    useState(false);

  const [qrDecoded, setQrDecoded] =
    useState(false);

  const [qrError, setQrError] =
    useState<string | null>(null);

  const canStart =
    Boolean(props.caseName.trim()) &&
    Boolean(props.evidenceType) &&
    (
      props.evidenceType === 'qr'
        ? Boolean(
            props.qrFile ||
            props.evidenceValue.trim()
          )
        : Boolean(
            props.evidenceValue.trim()
          )
    );

  // ──────────────────────────────────────────────────────────────────────────
  // REAL QR FILE SELECTION
  // ──────────────────────────────────────────────────────────────────────────

  const handleQrFileUpload = (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];

    if (!file) {
      return;
    }

    setQrError(null);
    setQrDecoded(false);

    if (!file.type.startsWith('image/')) {
      setQrError(
        'Please select a valid QR image file.'
      );

      e.target.value = '';
      return;
    }

    // Store the REAL image file.
    props.setQrFile(file);

    // Clear manual QR content.
    props.setEvidenceValue('');

    /*
     * IMPORTANT:
     *
     * No fake URL is generated here.
     *
     * The actual image is sent to:
     *
     * POST /analyze/qr
     *
     * when Start Investigation is clicked.
     */
    setQrDecoded(true);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-fadeIn">

      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100">
          Create Investigation
        </h2>

        <p className="text-sm text-gray-500 mt-1">
          Start a new digital forensics investigation
        </p>
      </div>

      <StepIndicator current={0} />

      {/* Case Information */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6 space-y-4">

        <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          Case Information
        </h3>

        <div>
          <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">
            Case Name *
          </label>

          <input
            type="text"
            value={props.caseName}
            onChange={e =>
              props.setCaseName(e.target.value)
            }
            className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
            placeholder="e.g. Suspicious QR Code Investigation"
          />
        </div>

        <div>
          <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">
            Case Description
          </label>

          <textarea
            value={props.caseDescription}
            onChange={e =>
              props.setCaseDescription(e.target.value)
            }
            rows={3}
            className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all resize-none"
            placeholder="Describe the context of this investigation..."
          />
        </div>
      </div>

      {/* Evidence Type */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6 space-y-4">

        <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          Choose Evidence Type
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">

          {EVIDENCE_TYPES.map(e => {
            const Icon = e.icon;

            const active =
              props.evidenceType === e.type;

            return (
              <button
                key={e.type}
                onClick={() =>
                  props.setEvidenceType(e.type)
                }
                className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${
                  active
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400 glow-cyan'
                    : 'bg-[#0a0e14] border-gray-800 text-gray-500 hover:border-gray-700 hover:text-gray-300'
                }`}
              >
                <Icon className="w-6 h-6" />

                <span className="text-xs font-medium">
                  {e.label}
                </span>
              </button>
            );
          })}

        </div>

        {selectedEvidence && (
          <div className="animate-fadeIn space-y-3">

            <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">
              Evidence Value *
            </label>

            {/* ═══════════════════════════════════════════════════════════════
                QR INPUT
            ═══════════════════════════════════════════════════════════════ */}

            {props.evidenceType === 'qr' && (
              <div className="space-y-3">

                {/* Upload */}
                <div className="flex flex-wrap items-center gap-3">

                  <label className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-cyan-500/30 rounded-lg cursor-pointer transition-all text-sm text-gray-400 hover:text-cyan-400">

                    {qrDecoding ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Upload className="w-4 h-4" />
                    )}

                    <span>
                      {qrDecoding
                        ? 'Processing QR...'
                        : 'Upload QR Image'}
                    </span>

                    <input
                      type="file"
                      accept="image/png,image/jpeg,image/jpg,image/webp"
                      className="hidden"
                      onChange={handleQrFileUpload}
                      disabled={qrDecoding}
                    />

                  </label>

                  {props.qrFile && (
                    <span className="text-xs text-gray-400 font-mono">
                      {props.qrFile.name}
                    </span>
                  )}

                  {qrDecoded && props.qrFile && (
                    <span className="flex items-center gap-1.5 text-xs text-emerald-400 animate-fadeIn">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      QR image ready for analysis.
                    </span>
                  )}

                </div>

                {/* QR Error */}
                {qrError && (
                  <div className="flex items-center gap-2 text-xs text-red-400">
                    <AlertTriangle className="w-4 h-4" />
                    {qrError}
                  </div>
                )}

                <div className="flex items-center gap-2">
                  <div className="flex-1 h-px bg-gray-800" />

                  <span className="text-xs text-gray-600 font-mono">
                    OR
                  </span>

                  <div className="flex-1 h-px bg-gray-800" />
                </div>

                {/* Manual QR content */}
                <div className="relative">

                  <ImageIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />

                  <input
                    type="text"
                    value={props.evidenceValue}
                    onChange={e => {
                      props.setEvidenceValue(
                        e.target.value
                      );

                      // Manual content means we don't need
                      // the previously selected image.
                      props.setQrFile(null);

                      setQrDecoded(false);
                      setQrError(null);
                    }}
                    className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all font-mono"
                    placeholder="Paste QR content or URL"
                  />

                </div>

              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════
    EMAIL HEADER FORENSIC INPUT
═══════════════════════════════════════════════════════════════ */}

{props.evidenceType === 'email' && (
  <div className="space-y-3">

    <div className="flex items-center justify-between">

      <span className="text-[10px] font-mono text-cyan-500/70 uppercase tracking-wider">
        Raw Email Headers
      </span>

      <span className="text-[10px] font-mono text-gray-700">
        SPF / DKIM / DMARC / SPOOF ANALYSIS
      </span>

    </div>

    <textarea
      value={props.evidenceValue}
      onChange={e =>
        props.setEvidenceValue(e.target.value)
      }
      rows={14}
      spellCheck={false}
      className="w-full bg-[#080c12] border border-gray-800 rounded-xl px-4 py-3 text-xs text-gray-300 placeholder-gray-700 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all font-mono leading-relaxed resize-y"
      placeholder={`Paste the complete raw email headers here...

Example:

From: security@example.com
To: analyst@example.com
Subject: Security Alert
Date: Sat, 23 Aug 2026 12:30:00 +0530
Message-ID: <abc123@example.com>
Reply-To: security@example.com
Return-Path: <security@example.com>
Authentication-Results: mx.example.com;
    spf=pass;
    dkim=pass;
    dmarc=pass
Received: from mail.example.com
    by mx.example.com
    with ESMTPS
DKIM-Signature: v=1; a=rsa-sha256; ...
Received-SPF: pass
`}
    />

    <div className="flex items-start gap-2 px-3 py-2.5 bg-cyan-500/5 border border-cyan-500/10 rounded-lg">

      <ShieldCheck className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />

      <p className="text-[11px] text-gray-500 leading-relaxed">
        CTDE will examine authentication results, sender identity,
        Reply-To and Return-Path mismatches, Received headers,
        originating IP addresses, spoofing indicators and
        suspicious keywords.
      </p>

    </div>

  </div>
)}

{/* Normal evidence input */}
{props.evidenceType !== 'qr' &&
  props.evidenceType !== 'email' && (
    <input
      type="text"
      value={props.evidenceValue}
      onChange={e =>
        props.setEvidenceValue(
          e.target.value
        )
      }
      className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all font-mono"
      placeholder={
        selectedEvidence.placeholder
      }
    />
  )}

            <p className="text-xs text-gray-600 mt-1.5">
              {selectedEvidence.desc}
            </p>

          </div>
        )}

      </div>

      {/* Start */}
      <button
        onClick={props.onStart}
        disabled={!canStart}
        className="flex items-center gap-2 px-6 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-medium rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed group"
      >
        Start Investigation

        <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
      </button>

    </div>
  );
}


// ══════════════════════════════════════════════════════════════════════════════
// PROGRESS STEP
// ══════════════════════════════════════════════════════════════════════════════

function ProgressStep({
  evidenceType,
  evidenceValue,
  qrFile,
  onComplete,
  onReset,
}: {
  evidenceType: EvidenceType;
  evidenceValue: string;
  qrFile: File | null;
  onComplete: (result: InvestigationResult) => void;
  onReset: () => void;
}) {
  const [currentStep, setCurrentStep] =
    useState(0);

  const [completed, setCompleted] =
    useState<number[]>([]);

  const [error, setError] =
    useState<string | null>(null);

  const [ready, setReady] =
    useState(false);

  const resultRef =
    useRef<InvestigationResult | null>(null);

  const completedRef =
    useRef(false);

  const visibleSteps =
    PROGRESS_STEPS.filter(label => {

      if (
        label === 'APK Permission Analysis'
      ) {
        return evidenceType === 'apk';
      }

      if (
        label === 'QR Destination Analysis'
      ) {
        return evidenceType === 'qr';
      }

      if (
        label === 'Sender Verification'
      ) {
        return evidenceType === 'sender';
      }

      return true;
    });

  // ──────────────────────────────────────────────────────────────────────────
  // REAL BACKEND INVESTIGATION
  // ──────────────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    /*
     * IMPORTANT QR LOGIC:
     *
     * Uploaded QR image:
     *
     *     runQrInvestigation(qrFile)
     *
     * which sends:
     *
     *     POST /analyze/qr
     *
     * Manual QR URL/content:
     *
     *     runInvestigation('qr', evidenceValue)
     *
     * which sends:
     *
     *     POST /analyze
     */

    const investigation =
  evidenceType === 'qr' && qrFile
    ? runQrInvestigation(qrFile)
    : evidenceType === 'email'
    ? runEmailHeaderInvestigation(
        evidenceValue
      )
    : runInvestigation(
        evidenceType,
        evidenceValue
      );
    investigation
      .then(result => {

        if (!cancelled) {
          resultRef.current = result;
          setReady(true);
        }

      })
      .catch(err => {

        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : 'Investigation failed unexpectedly.'
          );
        }

      });

    return () => {
      cancelled = true;
    };

  }, [
    evidenceType,
    evidenceValue,
    qrFile,
  ]);

  // ──────────────────────────────────────────────────────────────────────────
  // PROGRESS ANIMATION
  // ──────────────────────────────────────────────────────────────────────────

  useEffect(() => {

    if (error) {
      return;
    }

    if (
      currentStep >=
      visibleSteps.length
    ) {

      if (
        ready &&
        resultRef.current &&
        !completedRef.current
      ) {

        completedRef.current = true;

        const timer = setTimeout(
          () =>
            onComplete(
              resultRef.current!
            ),
          400
        );

        return () =>
          clearTimeout(timer);
      }

      return;
    }

    const isNearEnd =
      currentStep >=
      visibleSteps.length - 3;

    const delay = isNearEnd
      ? 1200 + Math.random() * 800
      : 500 + Math.random() * 400;

    const timer = setTimeout(() => {

      setCompleted(prev => [
        ...prev,
        currentStep,
      ]);

      setCurrentStep(prev => prev + 1);

    }, delay);

    return () =>
      clearTimeout(timer);

  }, [
    currentStep,
    visibleSteps.length,
    onComplete,
    error,
    ready,
  ]);

  const overallPct = error
    ? 0
    : Math.round(
        (completed.length /
          visibleSteps.length) *
          100
      );

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fadeIn">

      <div>
        <h2 className="text-2xl font-bold text-gray-100">
          Forensic Processing
        </h2>

        <p className="text-sm text-gray-500 mt-1">
          Analyzing evidence:{' '}

          <span className="font-mono text-cyan-400">
            {evidenceType === 'qr' && qrFile
              ? qrFile.name
              : evidenceValue}
          </span>
        </p>
      </div>

      <StepIndicator current={1} />

      {/* Progress */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <div className="flex items-center justify-between mb-3">

          <span className="text-sm font-mono text-gray-400">
            Overall Progress
          </span>

          <span className="text-lg font-bold text-cyan-400 font-mono">
            {overallPct}%
          </span>

        </div>

        <div className="h-2 bg-[#0a0e14] rounded-full overflow-hidden">

          <div
            className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-500"
            style={{
              width: `${overallPct}%`,
            }}
          />

        </div>

      </div>

      {error ? (

        <div className="bg-red-500/5 border border-red-500/30 rounded-2xl p-6 space-y-4">

          <div className="flex items-center gap-2 text-red-400">

            <AlertTriangle className="w-5 h-5" />

            <h3 className="text-sm font-semibold">
              Investigation Failed
            </h3>

          </div>

          <p className="text-sm text-gray-400">
            {error}
          </p>

          <button
            onClick={onReset}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-sm font-medium rounded-lg transition-all"
          >
            <ArrowRight className="w-4 h-4 rotate-180" />
            Back to Create
          </button>

        </div>

      ) : (

        <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6 space-y-2">

          {visibleSteps.map(
            (label, i) => {

              const isDone =
                completed.includes(i);

              const isActive =
                i === currentStep &&
                !isDone;

              return (
                <div
                  key={label}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all ${
                    isActive
                      ? 'bg-cyan-500/5'
                      : ''
                  }`}
                >

                  {isDone ? (

                    <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />

                  ) : isActive ? (

                    <Loader2 className="w-5 h-5 text-cyan-400 animate-spin flex-shrink-0" />

                  ) : (

                    <div className="w-5 h-5 rounded-full border-2 border-gray-800 flex-shrink-0" />

                  )}

                  <span
                    className={`text-sm font-mono ${
                      isDone
                        ? 'text-gray-400'
                        : isActive
                        ? 'text-cyan-400'
                        : 'text-gray-700'
                    }`}
                  >
                    {label}
                  </span>

                  {isActive && (
                    <span className="ml-auto text-xs font-mono text-cyan-500/50 animate-blink">
                      processing...
                    </span>
                  )}

                </div>
              );
            }
          )}

          {currentStep >=
            visibleSteps.length &&
            !ready && (

              <div className="flex items-center gap-3 px-3 py-2.5 mt-2 bg-cyan-500/5 rounded-lg border border-cyan-500/10 animate-pulse">

                <Loader2 className="w-5 h-5 text-cyan-400 animate-spin flex-shrink-0" />

                <span className="text-sm font-mono text-cyan-400">
                  Finalizing analysis results...
                </span>

              </div>

            )}

        </div>

      )}

    </div>
  );
}


// ══════════════════════════════════════════════════════════════════════════════
// RESULT STEP
// ══════════════════════════════════════════════════════════════════════════════

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

  const {
    analysis,
    evidencePanel,
    timeline,
  } = props;

  const scoreColor =
    analysis.riskLevel === 'Safe'
      ? 'emerald'
      : analysis.riskLevel === 'Suspicious'
      ? 'yellow'
      : 'red';

  const aiConfidence =
    parseInt(
      analysis.aiExplanation.match(
        /\d+(?=%)/
      )?.[0] || '90'
    );

  const handleDownloadPDF = () => {

    if (props.savedInvestigation) {
      generatePDFReport(
        props.savedInvestigation
      );

    } else {

      props.onGenerateReport();

      setTimeout(() => {

        /*
         * NOTE:
         * This uses investigator name because that is how
         * the current storage lookup is implemented in the
         * existing project.
         */
        const tempInv =
          investigationStore
            .getByUser(
              props.investigator
            )
            .slice(-1)[0];

        if (tempInv) {
          generatePDFReport(tempInv);
        }

      }, 100);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">

        <div>

          <h2 className="text-2xl font-bold text-gray-100">
            Investigation Result
          </h2>

          <p className="text-sm text-gray-500 mt-1 font-mono">
            {props.caseId}
          </p>

        </div>

        <StepIndicator
          current={2}
          compact
        />

      </div>

      {/* Case Details */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          Case Details
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">

          <DetailField
            label="Case ID"
            value={props.caseId}
          />

          <DetailField
            label="Evidence Type"
            value={props.evidenceType.toUpperCase()}
          />

          <DetailField
            label="Investigator"
            value={props.investigator}
          />

          <DetailField
            label="Timestamp"
            value={new Date().toLocaleString()}
          />

        </div>

      </div>

      {/* Trust Score */}
      <div
        className={`bg-[#0f1620] border rounded-2xl p-6 card-hover border-${scoreColor}-500/30`}
      >

        <div className="flex flex-col sm:flex-row items-center gap-6">

          <TrustGauge
            score={analysis.trustScore}
            riskLevel={analysis.riskLevel}
          />

          <div className="flex-1 space-y-3">

            <h3 className="text-sm font-semibold text-gray-300">
              Digital Trust Score
            </h3>

            <div className="flex items-center gap-3 flex-wrap">

              <RiskBadgeLarge
                level={analysis.riskLevel}
              />

              <span className="text-xs text-gray-600 font-mono">
                Score: {analysis.trustScore}/100
              </span>

              <span className="text-xs text-cyan-400 font-mono">
                AI Confidence: {aiConfidence}%
              </span>

            </div>

            <p className="text-sm text-gray-500">
              {analysis.reasonBehindDecision}
            </p>

            {/* REAL SCORE BREAKDOWN */}
            <div className="mt-4 pt-4 border-t border-gray-800/60">

              <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
                Score Breakdown
              </p>

              <div className="space-y-2">

                {buildScoreBreakdown(
                  analysis
                ).map((factor, i) => (

                  <div
                    key={i}
                    className="flex items-start gap-2.5"
                  >

                    {factor.positive ? (

                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />

                    ) : (

                      <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />

                    )}

                    <div className="flex-1">

                      <span className="text-xs text-gray-300">
                        {factor.label}
                      </span>

                      <span
                        className={`text-xs font-mono ml-2 ${
                          factor.positive
                            ? 'text-emerald-400'
                            : 'text-yellow-400'
                        }`}
                      >
                        {factor.positive
                          ? '+'
                          : ''}
                        {factor.points}
                      </span>

                    </div>

                  </div>

                ))}

              </div>

            </div>

          </div>

        </div>

      </div>

      {/* Verification Modules */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">

          <Activity className="w-4 h-4 text-cyan-400" />

          Evidence Summary — Verification Modules

        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">

          {buildVerificationModules(
            analysis,
            evidencePanel
          ).map((mod, i) => (

            <div
              key={i}
              className="flex items-center gap-2.5 px-3 py-2.5 bg-[#0a0e14] border border-gray-800/50 rounded-lg"
            >

              <CheckCircle2
                className={`w-4 h-4 flex-shrink-0 ${
                  mod.passed
                    ? 'text-emerald-400'
                    : 'text-gray-700'
                }`}
              />

              <div className="min-w-0">

                <p className="text-xs font-medium text-gray-300 truncate">
                  {mod.name}
                </p>

                <p className="text-[10px] text-gray-600 font-mono truncate">
                  {mod.detail}
                </p>

              </div>

            </div>

          ))}

        </div>

      </div>
      {/* ═══════════════════════════════════════════════════════════════════════
    QR FORENSIC ANALYSIS
═══════════════════════════════════════════════════════════════════════ */}

{props.evidenceType === 'qr' && analysis.qr && (
  <div className="bg-[#0f1620] border border-cyan-500/20 rounded-2xl p-6">

    <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
      <QrCode className="w-4 h-4 text-cyan-400" />
      QR Forensic Analysis
    </h3>

    <div className="space-y-4">

      {/* Decode Status */}
      <div className="flex items-center justify-between px-4 py-3 bg-emerald-500/5 border border-emerald-500/20 rounded-xl">

        <div className="flex items-center gap-3">

          <CheckCircle2 className="w-5 h-5 text-emerald-400" />

          <div>
            <p className="text-sm font-medium text-gray-200">
              QR Code Decoded
            </p>

            <p className="text-xs text-gray-600 font-mono mt-0.5">
              Digital evidence successfully extracted
            </p>
          </div>

        </div>

        <span className="text-xs font-mono text-emerald-400">
          SUCCESS
        </span>

      </div>

      {/* Decoded Destination */}
      <div className="px-4 py-3 bg-[#0a0e14] border border-gray-800/60 rounded-xl">

        <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
          Decoded Destination
        </p>

        <p className="text-sm text-cyan-400 font-mono break-all">
          {analysis.qr.decodedUrl || 'No destination extracted'}
        </p>

      </div>

      {/* Analysis Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">

        {/* Reputation */}
        <div className="px-4 py-3 bg-[#0a0e14] border border-gray-800/60 rounded-xl">

          <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
            Destination Reputation
          </p>

          <p
            className={`text-sm font-semibold ${
              analysis.qr.reputation
                ?.toLowerCase()
                .includes('malicious')
                ? 'text-red-400'
                : analysis.qr.reputation
                    ?.toLowerCase()
                    .includes('suspicious')
                ? 'text-yellow-400'
                : 'text-emerald-400'
            }`}
          >
            {analysis.qr.reputation || 'Unknown'}
          </p>

        </div>

        {/* QR Risk */}
        <div className="px-4 py-3 bg-[#0a0e14] border border-gray-800/60 rounded-xl">

          <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
            QR Risk Level
          </p>

          <p
            className={`text-sm font-semibold ${
              analysis.qr.qrRiskLevel
                ?.toLowerCase()
                .includes('high') ||
              analysis.qr.qrRiskLevel
                ?.toLowerCase()
                .includes('danger')
                ? 'text-red-400'
                : analysis.qr.qrRiskLevel
                    ?.toLowerCase()
                    .includes('medium') ||
                  analysis.qr.qrRiskLevel
                    ?.toLowerCase()
                    .includes('suspicious')
                ? 'text-yellow-400'
                : 'text-emerald-400'
            }`}
          >
            {analysis.qr.qrRiskLevel || 'Unknown'}
          </p>

        </div>

        {/* Redirect Count */}
        <div className="px-4 py-3 bg-[#0a0e14] border border-gray-800/60 rounded-xl">

          <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
            Redirects Detected
          </p>

          <p className="text-sm font-semibold text-gray-300">
            {analysis.qr.redirects?.length ?? 0}
          </p>

        </div>

      </div>

      {/* Redirect Chain */}
      {analysis.qr.redirects &&
        analysis.qr.redirects.length > 0 && (
          <div className="px-4 py-3 bg-[#0a0e14] border border-yellow-500/10 rounded-xl">

            <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
              Redirect Chain
            </p>

            <div className="space-y-2">

              {analysis.qr.redirects.map(
                (redirect, index) => (
                  <div
                    key={index}
                    className="flex items-start gap-2"
                  >

                    <span className="text-[10px] font-mono text-gray-600 mt-0.5">
                      {index + 1}.
                    </span>

                    <span className="text-xs text-gray-400 font-mono break-all">
                      {redirect}
                    </span>

                  </div>
                )
              )}

            </div>

          </div>
        )}

    </div>

  </div>
)}
      {/* Evidence Panel */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">

          <Network className="w-4 h-4 text-cyan-400" />

          Evidence Panel

        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">

          <PanelItem
            icon={Globe}
            label="Original URL"
            value={evidencePanel.originalUrl}
          />

          <PanelItem
            icon={Eye}
            label="Resolved URL"
            value={evidencePanel.resolvedUrl}
          />

          <PanelItem
            icon={Server}
            label="IP Address"
            value={evidencePanel.ipAddress}
          />

          <PanelItem
            icon={Server}
            label="Hosting Provider"
            value={evidencePanel.hostingProvider}
          />

          <PanelItem
            icon={MapPin}
            label="Country"
            value={evidencePanel.country}
          />

          <PanelItem
            icon={Fingerprint}
            label="Registrar"
            value={evidencePanel.registrar}
          />

          <PanelItem
            icon={Lock}
            label="SSL Status"
            value={evidencePanel.sslStatus}
          />

          <PanelItem
            icon={FileText}
            label="WHOIS Status"
            value={evidencePanel.whoisStatus}
          />

          <PanelItem
            icon={Hash}
            label="SHA256 Hash"
            value={evidencePanel.sha256Hash}
            mono
          />

        </div>

      </div>
{/* ============================================================
    EMAIL HEADER FORENSIC ANALYSIS
============================================================ */}

{props.evidenceType === 'email' && analysis.email && (
  <div className="bg-[#0f1620] border border-cyan-500/20 rounded-2xl p-6">
    <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
      <Mail className="w-4 h-4 text-cyan-400" />
      Email Header Forensic Analysis
    </h3>

    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">

      <ForensicEmailField
        label="SPF"
        value={analysis.email.spf}
        positive={analysis.email.spf.toLowerCase().includes('pass')}
      />

      <ForensicEmailField
        label="DKIM"
        value={analysis.email.dkim}
        positive={analysis.email.dkim.toLowerCase().includes('pass')}
      />

      <ForensicEmailField
        label="DMARC"
        value={analysis.email.dmarc}
        positive={analysis.email.dmarc.toLowerCase().includes('pass')}
      />

      <ForensicEmailField
        label="Sender Domain"
        value={analysis.email.senderDomain}
        positive={true}
      />

      <ForensicEmailField
        label="Reply-To Analysis"
        value={analysis.email.replyToAnalysis}
        positive={analysis.email.replyToAnalysis.toLowerCase().includes('match')}
      />

      <ForensicEmailField
        label="Spoof Detection"
        value={analysis.email.spoofDetection}
        positive={analysis.email.spoofDetection.toLowerCase().includes('no')}
      />

    </div>

    <div className="mt-4 px-4 py-3 bg-[#0a0e14] border border-gray-800/60 rounded-xl">
      <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
        Header Investigation Summary
      </p>

      <p className="text-xs text-gray-400 leading-relaxed">
        {analysis.evidenceSummary}
      </p>
    </div>
  </div>
)}
      {/* Analysis */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        <AnalysisCard
          title="Evidence Summary"
          content={analysis.evidenceSummary}
        />

        <AnalysisCard
          title="Identity Verification"
          content={analysis.identityVerification}
        />

        <AnalysisCard
          title="Domain Verification"
          content={analysis.domainVerification}
        />

        <AnalysisCard
          title="Certificate Details"
          content={analysis.certificateValidation}
        />

        <AnalysisCard
          title="WHOIS Information"
          content={analysis.whoisInfo}
        />

        <AnalysisCard
          title="Brand Impersonation"
          content={analysis.brandImpersonation}
        />

        <AnalysisCard
          title="URL Analysis"
          content={analysis.urlAnalysis}
        />

        {analysis.apkPermissionAnalysis && (
          <AnalysisCard
            title="APK Permission Analysis"
            content={
              analysis.apkPermissionAnalysis
            }
          />
        )}

        {analysis.senderVerification && (
          <AnalysisCard
            title="Sender Verification"
            content={
              analysis.senderVerification
            }
          />
        )}

        {analysis.qrVerification && (
          <AnalysisCard
            title="QR Destination Verification"
            content={
              analysis.qrVerification
            }
          />
        )}

        <AnalysisCard
          title="Reputation Analysis"
          content={analysis.reputationAnalysis}
        />

      </div>

      {/* MITRE */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-3">
          MITRE ATT&CK Mapping
        </h3>

        <div className="flex flex-wrap gap-2">

          {analysis.mitreMapping.map(
            (m, i) => (

              <span
                key={i}
                className="text-xs font-mono px-3 py-1.5 bg-[#0a0e14] border border-gray-800 rounded-lg text-gray-400"
              >
                {m}
              </span>
            )
          )}

        </div>

      </div>

      {/* AI Explanation */}
      <div className="bg-[#0f1620] border border-cyan-500/20 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">

          <Bot className="w-4 h-4 text-cyan-400" />

          AI Explanation

        </h3>

        <p className="text-sm text-gray-400 leading-relaxed">
          {analysis.aiExplanation}
        </p>

      </div>

      {/* AI Summary */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">

          <Bot className="w-4 h-4 text-emerald-400" />

          AI Summary

        </h3>

        <p className="text-sm text-gray-400 leading-relaxed">
          {analysis.aiSummary}
        </p>

      </div>

      {/* Recommendations */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">

          <Lightbulb className="w-4 h-4 text-yellow-400" />

          Recommendations

        </h3>

        <ul className="space-y-2">

          {analysis.recommendations.map(
            (r, i) => (

              <li
                key={i}
                className="flex items-start gap-2 text-sm text-gray-400"
              >

                <ChevronRight className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />

                {r}

              </li>

            )
          )}

        </ul>

      </div>

      {/* Timeline */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-6">

        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">

          <Clock className="w-4 h-4 text-cyan-400" />

          Investigation Timeline

        </h3>

        <div className="space-y-3">

          {timeline.map(
            (event, i) => (

              <div
                key={i}
                className="flex items-start gap-3"
              >

                <div className="flex flex-col items-center">

                  <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-cyan-500/10 flex-shrink-0 mt-1" />

                  {i <
                    timeline.length - 1 && (
                    <div className="w-px h-8 bg-gray-800 mt-1" />
                  )}

                </div>

                <div className="pb-2">

                  <p className="text-sm text-gray-300">
                    {event.label}
                  </p>

                  <p className="text-xs text-gray-600 font-mono">
                    {new Date(
                      event.timestamp
                    ).toLocaleTimeString()}
                  </p>

                </div>

              </div>
            )
          )}

        </div>

      </div>

      {/* Actions */}
      <div className="flex flex-col sm:flex-row gap-3">

        {!props.reportGenerated ? (

          <button
            onClick={
              props.onGenerateReport
            }
            className="flex items-center justify-center gap-2 px-6 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-medium rounded-lg transition-all"
          >

            <FileDown className="w-4 h-4" />

            Generate Report

          </button>

        ) : (

          <>

            <div className="flex items-center gap-2 px-4 py-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg text-sm">

              <CheckCircle2 className="w-4 h-4" />

              Report saved

            </div>

            <button
              onClick={
                handleDownloadPDF
              }
              className="flex items-center gap-2 px-4 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 text-sm font-medium rounded-lg transition-all"
            >

              <FileDown className="w-4 h-4" />

              Generate PDF

            </button>

            <button
              onClick={() =>
                props.onNavigate(
                  'reports'
                )
              }
              className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-all"
            >

              <FileText className="w-4 h-4" />

              View Reports

            </button>

            <button
              onClick={() =>
                props.onNavigate(
                  'assistant'
                )
              }
              className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-all"
            >

              <Bot className="w-4 h-4" />

              Ask AI

            </button>

            <button
              onClick={() =>
                props.onNavigate(
                  'dashboard'
                )
              }
              className="flex items-center gap-2 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-all ml-auto"
            >

              <LayoutDashboard className="w-4 h-4" />

              Return Dashboard

            </button>

          </>

        )}

      </div>

    </div>
  );
}


// ══════════════════════════════════════════════════════════════════════════════
// SHARED COMPONENTS
// ══════════════════════════════════════════════════════════════════════════════

function StepIndicator({
  current,
  compact,
}: {
  current: number;
  compact?: boolean;
}) {

  const steps = [
    'Create',
    'Progress',
    'Result',
  ];

  return (
    <div className="flex items-center gap-2">

      {steps.map((s, i) => (

        <div
          key={s}
          className="flex items-center gap-2"
        >

          <div
            className={`flex items-center gap-1.5 ${
              compact
                ? ''
                : 'px-3 py-1.5 rounded-lg'
            } ${
              i === current
                ? 'bg-cyan-500/10 text-cyan-400'
                : i < current
                ? 'text-emerald-400'
                : 'text-gray-700'
            }`}
          >

            <div
              className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                i === current
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                  : i < current
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                  : 'bg-[#0a0e14] text-gray-700 border border-gray-800'
              }`}
            >

              {i < current ? (
                <CheckCircle2 className="w-3 h-3" />
              ) : (
                i + 1
              )}

            </div>

            <span
              className={`text-xs font-medium ${
                compact
                  ? 'hidden sm:inline'
                  : ''
              }`}
            >
              {s}
            </span>

          </div>

          {i <
            steps.length - 1 && (

            <div
              className={`w-6 h-px ${
                i < current
                  ? 'bg-emerald-500/40'
                  : 'bg-gray-800'
              }`}
            />

          )}

        </div>

      ))}

    </div>
  );
}


function TrustGauge({
  score,
  riskLevel,
}: {
  score: number;
  riskLevel: RiskLevel;
}) {

  const circumference =
    2 * Math.PI * 45;

  const offset =
    circumference -
    (score / 100) *
      circumference;

  const color =
    riskLevel === 'Safe'
      ? '#00ff9d'
      : riskLevel === 'Suspicious'
      ? '#ffb800'
      : '#ff3b5c';

  return (
    <div className="relative w-32 h-32 flex-shrink-0">

      <svg
        className="w-full h-full -rotate-90"
        viewBox="0 0 100 100"
      >

        <circle
          cx="50"
          cy="50"
          r="45"
          fill="none"
          stroke="#1f2937"
          strokeWidth="6"
        />

        <circle
          cx="50"
          cy="50"
          r="45"
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{
            transition:
              'stroke-dashoffset 1s ease-out',
          }}
        />

      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">

        <span
          className="text-3xl font-bold"
          style={{ color }}
        >
          {score}
        </span>

        <span className="text-[10px] font-mono text-gray-600">
          / 100
        </span>

      </div>

    </div>
  );
}


function DetailField({
  label,
  value,
}: {
  label: string;
  value: string;
}) {

  return (
    <div>

      <p className="text-xs font-mono text-gray-600 uppercase tracking-wider mb-1">
        {label}
      </p>

      <p className="text-sm text-gray-300">
        {value}
      </p>

    </div>
  );
}


function PanelItem({
  icon: Icon,
  label,
  value,
  mono,
}: {
  icon: typeof Globe;
  label: string;
  value: string;
  mono?: boolean;
}) {

  return (
    <div className="flex items-start gap-2.5 px-3 py-2.5 bg-[#0a0e14] border border-gray-800/50 rounded-lg">

      <Icon className="w-4 h-4 text-gray-600 flex-shrink-0 mt-0.5" />

      <div className="min-w-0">

        <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider">
          {label}
        </p>

        <p
          className={`text-xs text-gray-400 ${
            mono
              ? 'font-mono break-all'
              : 'truncate'
          }`}
        >
          {value}
        </p>

      </div>

    </div>
  );
}


function AnalysisCard({
  title,
  content,
}: {
  title: string;
  content: string;
}) {

  return (
    <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-5 card-hover">

      <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">
        {title}
      </h4>

      <p className="text-sm text-gray-400 leading-relaxed">
        {content}
      </p>

    </div>
  );
}


function RiskBadgeLarge({
  level,
}: {
  level: RiskLevel;
}) {

  const map: Record<
    RiskLevel,
    {
      cls: string;
      icon: typeof ShieldCheck;
    }
  > = {

    Safe: {
      cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      icon: ShieldCheck,
    },

    Suspicious: {
      cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      icon: AlertTriangle,
    },

    Dangerous: {
      cls: 'bg-red-500/10 text-red-400 border-red-500/30',
      icon: ShieldAlert,
    },

  };

  const {
    cls,
    icon: Icon,
  } = map[level];

  return (
    <span
      className={`flex items-center gap-1.5 text-sm px-3 py-1 rounded-full border font-medium ${cls}`}
    >

      <Icon className="w-4 h-4" />

      {level}

    </span>
  );
}


// ══════════════════════════════════════════════════════════════════════════════
// REAL BACKEND SCORE BREAKDOWN
// ══════════════════════════════════════════════════════════════════════════════

function buildScoreBreakdown(
  analysis: AnalysisResult
): {
  label: string;
  positive: boolean;
  points: number;
}[] {
  return analysis.scoreBreakdown ?? [];
}


// ══════════════════════════════════════════════════════════════════════════════
// VERIFICATION MODULES
// ══════════════════════════════════════════════════════════════════════════════

function buildVerificationModules(
  analysis: AnalysisResult,
  _evidencePanel: EvidencePanel
): {
  name: string;
  detail: string;
  passed: boolean;
}[] {

  return [

    {
      name: 'Identity Verification',
      detail: analysis.identityVerification.includes(
        'valid'
      )
        ? 'Verified'
        : 'Unverified',
      passed:
        analysis.identityVerification.includes(
          'valid'
        ),
    },

    {
      name: 'Domain Verification',
      detail: analysis.domainVerification.includes(
        'resolves'
      )
        ? 'Resolved'
        : 'Failed',
      passed:
        analysis.domainVerification.includes(
          'resolves'
        ),
    },

    {
      name: 'Certificate Validation',
      detail:
        analysis.certificateValidation.includes(
          'Valid'
        )
          ? 'Valid TLS'
          : 'No SSL',
      passed:
        analysis.certificateValidation.includes(
          'Valid'
        ),
    },

    {
      name: 'WHOIS Lookup',
      detail:
        analysis.whoisInfo.includes('public')
          ? 'Public'
          : 'Privacy',
      passed: true,
    },

    {
      name: 'Brand Detection',
      detail:
        analysis.brandImpersonation.includes(
          'No known'
        )
          ? 'Clean'
          : 'Flagged',
      passed:
        analysis.brandImpersonation.includes(
          'No known'
        ),
    },

    {
      name: 'URL Analysis',
      detail:
        analysis.urlAnalysis.includes('clean')
          ? 'Clean'
          : 'Anomalies',
      passed:
        analysis.urlAnalysis.includes('clean'),
    },

    {
      name: 'Reputation Analysis',
      detail:
        analysis.reputationAnalysis.includes(
          'no entries'
        )
          ? 'Clean'
          : 'Flagged',
      passed:
        analysis.reputationAnalysis.includes(
          'no entries'
        ),
    },

    {
      name: 'MITRE ATT&CK Mapping',
      detail: `${analysis.mitreMapping.length} techniques`,
      passed: true,
    },

    {
      name: 'AI Summary Generation',
      detail: 'Complete',
      passed: true,
    },

  ];
}

function ForensicEmailField({
  label,
  value,
  positive,
}: {
  label: string;
  value: string;
  positive: boolean;
}) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
      <div className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-400">
        {label}
      </div>

      <div
        className={`text-sm font-semibold ${
          positive ? 'text-emerald-400' : 'text-red-400'
        }`}
      >
        {value}
      </div>
    </div>
  );
}