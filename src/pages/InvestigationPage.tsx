import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore } from '../lib/storage';
import { generateCaseId, generatePDFReport } from '../lib/investigationEngine';

import {
  runInvestigation,
  runEmailHeaderInvestigation,
  runQrInvestigation,
  runApkInvestigation,
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
    label: 'Website / Link',
    icon: Globe,
    desc: 'Check whether a website or link looks safe',
    placeholder: 'Paste the website link here',
  },
  {
    type: 'email',
    label: 'Email / Message',
    icon: Mail,
    desc: 'Check whether an email message may be fake or suspicious',
    placeholder: 'Paste the email headers here',
  },
  {
    type: 'apk',
    label: 'Android App',
    icon: Smartphone,
    desc: 'Check an Android APK file for suspicious permissions and activity',
    placeholder: 'Select an APK file',
  },
  {
    type: 'qr',
    label: 'QR Code',
    icon: QrCode,
    desc: 'Check where a QR code leads before you open it',
    placeholder: 'Upload a QR image or paste its content',
  },
  {
    type: 'sender',
    label: 'Sender / SMS',
    icon: Send,
    desc: 'Check whether a sender, SMS ID or messaging identity looks genuine',
    placeholder: 'Enter the sender name or number',
  },
];

const PROGRESS_STEPS = [
  'Preparing your check',
  'Checking identity',
  'Checking website details',
  'Checking security certificate',
  'Checking website registration',
  'Checking for fake branding',
  'Checking website reputation',
  'Checking app permissions',
  'Checking QR destination',
  'Checking sender',
  'Analyzing security signals',
  'Preparing simple explanation',
  'Preparing safety result',
  'Preparing report',
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

  // REAL APK FILE
  const [apkFile, setApkFile] = useState<File | null>(null);

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
    if (!evidenceType) {
      return;
    }

    // Public-user mode: case names are generated automatically so the
    // user does not have to understand forensic case management.
    if (!caseName.trim()) {
      const selectedLabel =
        EVIDENCE_TYPES.find(e => e.type === evidenceType)?.label ||
        'Security Check';

      setCaseName(`${selectedLabel} Check`);
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

    // APK requires the actual APK binary.
    if (
      evidenceType === 'apk' &&
      !apkFile
    ) {
      return;
    }

    // All other evidence types require text input.
    if (
      evidenceType !== 'qr' &&
      evidenceType !== 'apk' &&
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

    // IMPORTANT: clear uploaded files
    setQrFile(null);
    setApkFile(null);

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

          if (type !== 'apk') {
            setApkFile(null);
          }

          setEvidenceValue('');
        }}
        evidenceValue={evidenceValue}
        setEvidenceValue={setEvidenceValue}
        qrFile={qrFile}
        setQrFile={setQrFile}
        apkFile={apkFile}
        setApkFile={setApkFile}
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
        apkFile={apkFile}
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

  apkFile: File | null;
  setApkFile: (file: File | null) => void;

  onStart: () => void;
}) {
  const selectedEvidence = EVIDENCE_TYPES.find(
    e => e.type === props.evidenceType
  );

  const [qrDecoding] = useState(false);
  const [qrDecoded, setQrDecoded] = useState(false);
  const [qrError, setQrError] = useState<string | null>(null);

  const canStart =
    Boolean(props.evidenceType) &&
    (
      props.evidenceType === 'qr'
        ? Boolean(props.qrFile || props.evidenceValue.trim())
        : props.evidenceType === 'apk'
        ? Boolean(props.apkFile)
        : Boolean(props.evidenceValue.trim())
    );

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
      setQrError('Please choose a valid QR image.');
      e.target.value = '';
      return;
    }

    props.setQrFile(file);
    props.setEvidenceValue('');
    setQrDecoded(true);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">

      {/* ============================================================
          SIMPLE PUBLIC-USER HEADER
      ============================================================ */}
      <div className="text-center max-w-2xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/5 border border-cyan-500/10 mb-4">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">
            CyberVerify AI
          </span>
        </div>

        <h2 className="text-2xl sm:text-3xl font-bold text-gray-100">
          Is it safe?
        </h2>

        <p className="text-sm text-gray-500 mt-2 leading-relaxed">
          Choose what you want to check. We will analyze it and explain the
          result in simple language.
        </p>
      </div>

      {/* ============================================================
          STEP INDICATOR
      ============================================================ */}
      <StepIndicator current={0} />

      {/* ============================================================
          CHOOSE WHAT TO CHECK
      ============================================================ */}
      <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-5 sm:p-6">

        <div className="mb-5">
          <h3 className="text-base font-semibold text-gray-200 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            What do you want to check?
          </h3>

          <p className="text-xs text-gray-600 mt-1.5">
            Select one option below. You do not need to know any technical terms.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {EVIDENCE_TYPES.map(e => {
            const Icon = e.icon;
            const active = props.evidenceType === e.type;

            return (
              <button
                key={e.type}
                onClick={() => props.setEvidenceType(e.type)}
                className={`text-left p-4 rounded-xl border transition-all duration-200 group ${
                  active
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400 shadow-[0_0_20px_rgba(34,211,238,0.06)]'
                    : 'bg-[#0a0e14] border-gray-800 text-gray-400 hover:border-gray-700 hover:text-gray-200'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-3">
                  <Icon className="w-6 h-6" />

                  {active && (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  )}
                </div>

                <span className="block text-sm font-semibold">
                  {e.label}
                </span>

                <span className="block text-[11px] text-gray-600 group-hover:text-gray-500 mt-1.5 leading-relaxed">
                  {e.desc}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ============================================================
          INPUT
      ============================================================ */}
      {selectedEvidence && (
        <div className="bg-[#0f1620] border border-gray-800/60 rounded-2xl p-5 sm:p-6 space-y-4 animate-fadeIn">

          <div>
            <h3 className="text-base font-semibold text-gray-200">
              {selectedEvidence.label}
            </h3>

            <p className="text-xs text-gray-600 mt-1">
              {selectedEvidence.desc}
            </p>
          </div>

          {/* APK */}
          {props.evidenceType === 'apk' && (
            <div className="space-y-3">
              <label className="flex items-center gap-3 px-4 py-5 bg-[#0a0e14] border border-dashed border-gray-800 hover:border-cyan-500/40 rounded-xl cursor-pointer transition-all">
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0">
                  <Upload className="w-5 h-5 text-cyan-400" />
                </div>

                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-300">
                    Choose Android app file
                  </p>

                  <p className="text-xs text-gray-600 mt-1">
                    Select the .apk file you want to check.
                  </p>
                </div>

                <input
                  type="file"
                  accept=".apk,application/vnd.android.package-archive"
                  className="hidden"
                  onChange={e => {
                    const file = e.target.files?.[0];

                    if (!file) {
                      return;
                    }

                    if (!file.name.toLowerCase().endsWith('.apk')) {
                      alert('Please choose a valid Android APK file.');
                      e.target.value = '';
                      return;
                    }

                    props.setApkFile(file);
                    props.setEvidenceValue(file.name);
                  }}
                />
              </label>

              {props.apkFile && (
                <div className="flex items-center gap-3 px-4 py-3 bg-emerald-500/5 border border-emerald-500/20 rounded-lg">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />

                  <div className="min-w-0">
                    <p className="text-sm text-gray-300 truncate">
                      {props.apkFile.name}
                    </p>

                    <p className="text-xs text-gray-600 mt-1">
                      {(props.apkFile.size / (1024 * 1024)).toFixed(2)} MB • Ready to check
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* QR */}
          {props.evidenceType === 'qr' && (
            <div className="space-y-4">
              <label className="flex items-center gap-3 px-4 py-5 bg-[#0a0e14] border border-dashed border-gray-800 hover:border-cyan-500/40 rounded-xl cursor-pointer transition-all">
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0">
                  {qrDecoding ? (
                    <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                  ) : (
                    <QrCode className="w-5 h-5 text-cyan-400" />
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-300">
                    Upload a QR code image
                  </p>

                  <p className="text-xs text-gray-600 mt-1">
                    We will read the QR code and check where it leads.
                  </p>
                </div>

                <input
                  type="file"
                  accept="image/png,image/jpeg,image/jpg,image/webp"
                  className="hidden"
                  onChange={handleQrFileUpload}
                  disabled={qrDecoding}
                />
              </label>

              {props.qrFile && (
                <div className="flex items-center gap-2 text-xs text-gray-400">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  {props.qrFile.name} is ready to check.
                </div>
              )}

              {qrError && (
                <div className="flex items-center gap-2 text-xs text-red-400">
                  <AlertTriangle className="w-4 h-4" />
                  {qrError}
                </div>
              )}

              <div className="flex items-center gap-2">
                <div className="flex-1 h-px bg-gray-800" />
                <span className="text-xs text-gray-600">OR</span>
                <div className="flex-1 h-px bg-gray-800" />
              </div>

              <input
                type="text"
                value={props.evidenceValue}
                onChange={e => {
                  props.setEvidenceValue(e.target.value);
                  props.setQrFile(null);
                  setQrDecoded(false);
                  setQrError(null);
                }}
                className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-3 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                placeholder="Or paste the QR link here"
              />
            </div>
          )}

          {/* Email */}
          {props.evidenceType === 'email' && (
            <div className="space-y-3">
              <textarea
                value={props.evidenceValue}
                onChange={e => props.setEvidenceValue(e.target.value)}
                rows={12}
                spellCheck={false}
                className="w-full bg-[#080c12] border border-gray-800 rounded-xl px-4 py-3 text-xs text-gray-300 placeholder-gray-700 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all font-mono leading-relaxed resize-y"
                placeholder={`Paste the email headers here.\n\nIf you do not know what email headers are, open the suspicious email and use your email service's option to view the original message or headers.`}
              />

              <div className="flex items-start gap-2 px-3 py-2.5 bg-cyan-500/5 border border-cyan-500/10 rounded-lg">
                <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <p className="text-[11px] text-gray-500 leading-relaxed">
                  We check sender details, authentication results and signs of spoofing.
                </p>
              </div>
            </div>
          )}

          {/* Sender */}
          {props.evidenceType === 'sender' && (
            <div className="space-y-3">
              <input
                type="text"
                value={props.evidenceValue}
                onChange={e => props.setEvidenceValue(e.target.value)}
                className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-3 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                placeholder="Example: Amazon, VK-HDFCBK, +91 98765 43210"
              />
            </div>
          )}

          {/* Website / normal input */}
          {props.evidenceType !== 'qr' &&
            props.evidenceType !== 'email' &&
            props.evidenceType !== 'apk' && (
              <input
                type="text"
                value={props.evidenceValue}
                onChange={e => props.setEvidenceValue(e.target.value)}
                className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-3 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                placeholder={selectedEvidence.placeholder}
              />
            )}
        </div>
      )}

      {/* ============================================================
          CHECK BUTTON
      ============================================================ */}
      <div className="flex justify-center">
        <button
          onClick={props.onStart}
          disabled={!canStart}
          className="flex items-center justify-center gap-2 min-w-52 px-7 py-3 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-semibold rounded-xl transition-all disabled:opacity-30 disabled:cursor-not-allowed group"
        >
          <ShieldCheck className="w-4 h-4" />
          Check Now
          <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>

      <p className="text-center text-[10px] text-gray-700 font-mono">
        CyberVerify AI checks the information you provide and explains the result.
      </p>

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
  apkFile,
  onComplete,
  onReset,
}: {
  evidenceType: EvidenceType;
  evidenceValue: string;
  qrFile: File | null;
  apkFile: File | null;
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
        label === 'Checking app permissions'
      ) {
        return evidenceType === 'apk';
      }

      if (
        label === 'Checking QR destination'
      ) {
        return evidenceType === 'qr';
      }

      if (
        label === 'Checking sender'
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
      evidenceType === 'apk' && apkFile
        ? runApkInvestigation(apkFile)
        : evidenceType === 'qr' && qrFile
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
    apkFile,
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
          Checking your information
        </h2>

        <p className="text-sm text-gray-500 mt-1">
          Checking:{' '}

          <span className="font-mono text-cyan-400">
            {evidenceType === 'apk' && apkFile
              ? apkFile.name
              : evidenceType === 'qr' && qrFile
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
            Check Progress
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
              We could not complete the check
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
            Try Again
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
                  Preparing your result...
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

  const aiConfidence =
    parseInt(
      analysis.aiExplanation.match(/\d+(?=%)/)?.[0] || '90',
    );

  const resultConfig = {
    Safe: {
      title: 'Looks Safe',
      description:
        'We did not find major security concerns in the checks performed.',
      icon: ShieldCheck,
      iconClass: 'text-emerald-400',
      borderClass: 'border-emerald-500/25',
      bgClass: 'bg-emerald-500/5',
    },
    Suspicious: {
      title: 'Be Careful',
      description:
        'Some findings need your attention before you continue.',
      icon: AlertTriangle,
      iconClass: 'text-yellow-400',
      borderClass: 'border-yellow-500/25',
      bgClass: 'bg-yellow-500/5',
    },
    Dangerous: {
      title: 'High Risk',
      description:
        'This check found signs that may indicate a security threat.',
      icon: ShieldAlert,
      iconClass: 'text-red-400',
      borderClass: 'border-red-500/25',
      bgClass: 'bg-red-500/5',
    },
  }[analysis.riskLevel];

  const ResultIcon = resultConfig.icon;

  const evidenceLabel = {
    url: 'Website / Link',
    email: 'Email / Message',
    apk: 'Android App',
    qr: 'QR Code',
    sender: 'Sender / SMS',
  }[props.evidenceType];

  const handleDownloadPDF = () => {
    if (props.savedInvestigation) {
      generatePDFReport(props.savedInvestigation);
    } else {
      props.onGenerateReport();
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">

      {/* =========================================================
          RESULT HEADER
      ========================================================= */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-emerald-400/70">
              CHECK COMPLETE
            </span>
          </div>

          <h2 className="text-2xl font-bold text-gray-100">
            Your Safety Check Result
          </h2>

          <p className="text-sm text-gray-600 mt-1">
            {evidenceLabel}
          </p>
        </div>

        <StepIndicator current={2} compact />
      </div>

      {/* =========================================================
          SIMPLE RESULT
      ========================================================= */}
      <section
        className={`rounded-2xl border ${resultConfig.borderClass} ${resultConfig.bgClass} bg-[#0f1620] p-6 sm:p-8`}
      >
        <div className="flex flex-col items-center text-center">

          <div className="w-16 h-16 rounded-2xl bg-[#0a0e14] border border-gray-800 flex items-center justify-center">
            <ResultIcon className={`w-8 h-8 ${resultConfig.iconClass}`} />
          </div>

          <h1 className="text-3xl font-bold text-gray-100 mt-5">
            {resultConfig.title}
          </h1>

          <p className="text-sm text-gray-500 max-w-xl mt-2 leading-relaxed">
            {resultConfig.description}
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <div className="px-5 py-3 rounded-xl bg-[#0a0e14] border border-gray-800">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">
                Safety Score
              </p>
              <p className="text-2xl font-bold text-gray-100 mt-1">
                {analysis.trustScore}
                <span className="text-sm text-gray-600">/100</span>
              </p>
            </div>

            <div className="px-5 py-3 rounded-xl bg-[#0a0e14] border border-gray-800">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">
                Check Type
              </p>
              <p className="text-sm font-semibold text-gray-300 mt-2">
                {evidenceLabel}
              </p>
            </div>
          </div>

        </div>
      </section>

      {/* =========================================================
          WHAT WE FOUND
      ========================================================= */}
      <section className="rounded-2xl border border-gray-800/60 bg-[#0f1620] p-6">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Eye className="w-4 h-4 text-cyan-400" />
          What We Found
        </h3>

        <p className="text-sm text-gray-500 leading-relaxed mt-3">
          {analysis.evidenceSummary}
        </p>
      </section>

      {/* =========================================================
          SIMPLE EXPLANATION
      ========================================================= */}
      <section className="rounded-2xl border border-purple-500/15 bg-[#0f1620] p-6">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Bot className="w-4 h-4 text-purple-400" />
          Simple Explanation
        </h3>

        <p className="text-sm text-gray-500 leading-relaxed mt-3">
          {analysis.aiSummary || analysis.aiExplanation}
        </p>
      </section>

      {/* =========================================================
          WHAT SHOULD YOU DO
      ========================================================= */}
      <section className="rounded-2xl border border-gray-800/60 bg-[#0f1620] p-6">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-yellow-400" />
          What Should You Do?
        </h3>

        <ul className="mt-4 space-y-2.5">
          {analysis.recommendations.map((recommendation, index) => (
            <li
              key={index}
              className="flex items-start gap-2.5 text-sm text-gray-500 leading-relaxed"
            >
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>{recommendation}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* =========================================================
          TECHNICAL DETAILS
      ========================================================= */}
      <details className="rounded-2xl border border-gray-800/60 bg-[#0f1620] overflow-hidden">
        <summary className="cursor-pointer list-none px-6 py-5 hover:bg-cyan-500/[0.02] transition-colors">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-gray-300">
                Technical Details
              </h3>
              <p className="text-[10px] text-gray-700 mt-1">
                Advanced security and investigation information
              </p>
            </div>

            <ChevronRight className="w-4 h-4 text-gray-600 transition-transform" />
          </div>
        </summary>

        <div className="border-t border-gray-800/60 p-6 space-y-5">

          {/* Basic technical information */}
          <div>
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Check Information
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              <DetailField label="Case ID" value={props.caseId} />
              <DetailField label="Evidence Type" value={evidenceLabel} />
              <DetailField
                label="Trust Score"
                value={`${analysis.trustScore}/100`}
              />
              <DetailField
                label="Risk Level"
                value={analysis.riskLevel}
              />
              <DetailField
                label="AI Confidence"
                value={`${aiConfidence}%`}
              />
              <DetailField
                label="Investigator"
                value={props.investigator}
              />
            </div>
          </div>

          {/* Score reasoning */}
          <div className="rounded-xl bg-[#0a0e14] border border-gray-800/60 p-4">
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Decision Reasoning
            </h4>

            <p className="text-sm text-gray-500 leading-relaxed">
              {analysis.reasonBehindDecision}
            </p>
          </div>

          {/* Score breakdown */}
          <div>
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Score Breakdown
            </h4>

            <div className="space-y-2">
              {buildScoreBreakdown(analysis).map((factor, index) => (
                <div
                  key={index}
                  className="flex items-start gap-2.5 rounded-lg bg-[#0a0e14] border border-gray-800/50 px-3 py-2.5"
                >
                  {factor.positive ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
                  )}

                  <span className="text-xs text-gray-400 flex-1">
                    {factor.label}
                  </span>

                  <span
                    className={`text-xs font-mono ${
                      factor.positive
                        ? 'text-emerald-400'
                        : 'text-yellow-400'
                    }`}
                  >
                    {factor.positive ? '+' : ''}
                    {factor.points}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Verification modules */}
          <div>
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Verification Checks
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {buildVerificationModules(
                analysis,
                evidencePanel,
              ).map((mod, index) => (
                <div
                  key={index}
                  className="flex items-center gap-2.5 px-3 py-2.5 bg-[#0a0e14] border border-gray-800/50 rounded-lg"
                >
                  <CheckCircle2
                    className={`w-4 h-4 shrink-0 ${
                      mod.passed
                        ? 'text-emerald-400'
                        : 'text-gray-700'
                    }`}
                  />

                  <div className="min-w-0">
                    <p className="text-xs font-medium text-gray-300 truncate">
                      {mod.name}
                    </p>
                    <p className="text-[10px] text-gray-600 truncate">
                      {mod.detail}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence details */}
          <div>
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Evidence Details
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <PanelItem
                icon={Globe}
                label="Website / Link"
                value={evidencePanel.originalUrl}
              />
              <PanelItem
                icon={Eye}
                label="Final Website"
                value={evidencePanel.resolvedUrl}
              />
              <PanelItem
                icon={Server}
                label="Server Address"
                value={evidencePanel.ipAddress}
              />
              <PanelItem
                icon={Server}
                label="Hosting Service"
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
                label="Security Certificate"
                value={evidencePanel.sslStatus}
              />
              <PanelItem
                icon={FileText}
                label="Registration Check"
                value={evidencePanel.whoisStatus}
              />
              <PanelItem
                icon={Hash}
                label="File Fingerprint"
                value={evidencePanel.sha256Hash}
                mono
              />
            </div>
          </div>

          {/* QR details */}
          {props.evidenceType === 'qr' && analysis.qr && (
            <div>
              <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
                QR Code Analysis
              </h4>

              <div className="space-y-3">
                <div className="rounded-xl bg-[#0a0e14] border border-gray-800/60 p-4">
                  <p className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mb-2">
                    Decoded Destination
                  </p>
                  <p className="text-sm text-cyan-400 font-mono break-all">
                    {analysis.qr.decodedUrl || 'No destination extracted'}
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <DetailField
                    label="Destination Reputation"
                    value={analysis.qr.reputation || 'Unknown'}
                  />
                  <DetailField
                    label="QR Risk Level"
                    value={analysis.qr.qrRiskLevel || 'Unknown'}
                  />
                  <DetailField
                    label="Redirects"
                    value={String(analysis.qr.redirects?.length ?? 0)}
                  />
                </div>

                {analysis.qr.redirects &&
                  analysis.qr.redirects.length > 0 && (
                    <div className="rounded-xl bg-[#0a0e14] border border-gray-800/60 p-4">
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
                              <span className="text-[10px] font-mono text-gray-600">
                                {index + 1}.
                              </span>
                              <span className="text-xs text-gray-400 font-mono break-all">
                                {redirect}
                              </span>
                            </div>
                          ),
                        )}
                      </div>
                    </div>
                  )}
              </div>
            </div>
          )}

          {/* Email details */}
          {props.evidenceType === 'email' && analysis.email && (
            <div>
              <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
                Email Security Analysis
              </h4>

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
            </div>
          )}

          {/* Analysis details */}
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
                content={analysis.apkPermissionAnalysis}
              />
            )}

            {analysis.senderVerification && (
              <AnalysisCard
                title="Sender Verification"
                content={analysis.senderVerification}
              />
            )}

            {analysis.qrVerification && (
              <AnalysisCard
                title="QR Destination Verification"
                content={analysis.qrVerification}
              />
            )}

            <AnalysisCard
              title="Reputation Analysis"
              content={analysis.reputationAnalysis}
            />
          </div>

          {/* MITRE / security signals */}
          <div>
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Security Signals
            </h4>

            <div className="flex flex-wrap gap-2">
              {analysis.mitreMapping.map((mapping, index) => (
                <span
                  key={index}
                  className="text-xs font-mono px-3 py-1.5 bg-[#0a0e14] border border-gray-800 rounded-lg text-gray-400"
                >
                  {mapping}
                </span>
              ))}
            </div>
          </div>

          {/* AI technical explanation */}
          <div className="rounded-xl bg-[#0a0e14] border border-gray-800/60 p-4">
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">
              AI Analysis
            </h4>

            <p className="text-sm text-gray-500 leading-relaxed">
              {analysis.aiExplanation}
            </p>
          </div>

          {/* Timeline */}
          <div>
            <h4 className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">
              Investigation Timeline
            </h4>

            <div className="space-y-3">
              {timeline.map((event, index) => (
                <div
                  key={index}
                  className="flex items-start gap-3"
                >
                  <div className="flex flex-col items-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-cyan-500/10 shrink-0 mt-1" />

                    {index < timeline.length - 1 && (
                      <div className="w-px h-8 bg-gray-800 mt-1" />
                    )}
                  </div>

                  <div className="pb-2">
                    <p className="text-sm text-gray-400">
                      {event.label}
                    </p>
                    <p className="text-xs text-gray-600 font-mono">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </details>

      {/* =========================================================
          ACTIONS
      ========================================================= */}
      <div className="flex flex-col sm:flex-row gap-3">

        <button
          onClick={handleDownloadPDF}
          className="flex items-center justify-center gap-2 flex-1 px-6 py-3 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-semibold rounded-xl transition-all"
        >
          <FileDown className="w-4 h-4" />
          {props.reportGenerated ? 'Download Report' : 'Save & Download Report'}
        </button>

        <button
          onClick={props.onNewInvestigation}
          className="flex items-center justify-center gap-2 flex-1 px-6 py-3 bg-[#0f1620] hover:bg-gray-800/40 border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 font-semibold rounded-xl transition-all"
        >
          <ShieldCheck className="w-4 h-4" />
          Check Something Else
        </button>
      </div>

      {props.reportGenerated && (
        <div className="flex flex-col sm:flex-row justify-center gap-4 text-center">
          <button
            onClick={() => props.onNavigate('reports')}
            className="text-xs text-cyan-500/70 hover:text-cyan-400 transition-colors"
          >
            View My Reports →
          </button>

          <button
            onClick={() => props.onNavigate('assistant')}
            className="text-xs text-purple-500/70 hover:text-purple-400 transition-colors"
          >
            Ask CyberVerify about this result →
          </button>
        </div>
      )}

    </div>
  );
}

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
      name: 'Checking identity',
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
      name: 'Checking website details',
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
      name: 'Checking security certificate',
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
      name: 'Checking website registration',
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
      name: 'Security Signals',
      detail: `${analysis.mitreMapping.length} techniques`,
      passed: true,
    },

    {
      name: 'Preparing simple explanation',
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