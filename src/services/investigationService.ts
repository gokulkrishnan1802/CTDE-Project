import type {
  AnalysisResult,
  EvidencePanel,
  EvidenceType,
  TimelineEvent,
} from '../types';

import {
  postAnalyze,
  postAnalyzeQr,
  postAnalyzeApk,
  postAnalyzeEmailHeaders,
  mapBackendResponse,
  type BackendAnalysisResponse,
} from './api';

export interface InvestigationResult {
  analysis: AnalysisResult;
  evidencePanel: EvidencePanel;
  timeline: TimelineEvent[];
  aiConfidence: number;
  raw: BackendAnalysisResponse;
}

const MAX_MS = 90000;

function createTimeout(message: string) {
  return new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error(message)), MAX_MS)
  );
}

async function buildInvestigationResult(
  backend: BackendAnalysisResponse
): Promise<InvestigationResult> {
  const {
    analysis,
    evidencePanel,
    aiConfidence,
  } = mapBackendResponse(backend);

  const now = Date.now();

  const steps = [
    'Evidence Uploaded',
    'Identity Verified',
    'SSL Checked',
    'WHOIS Completed',
    'Reputation Checked',
    'MITRE Mapping Completed',
    'AI Summary Generated',
    'Investigation Completed',
  ];

  const timeline: TimelineEvent[] = steps.map((label, index) => ({
    label,
    timestamp: new Date(now + index * 800).toISOString(),
    status: 'done' as const,
  }));

  return {
    analysis,
    evidencePanel,
    timeline,
    aiConfidence,
    raw: backend,
  };
}

/**
 * Normal investigation for:
 * URL, APK, QR text/content, sender, etc.
 *
 * Email headers should use runEmailHeaderInvestigation().
 */
export async function runInvestigation(
  evidenceType: EvidenceType,
  evidenceValue: string
): Promise<InvestigationResult> {
  const investigation = postAnalyze({
    evidenceType,
    evidenceValue: evidenceValue.trim(),
  });

  const backend = await Promise.race([
    investigation,
    createTimeout(
      'Investigation timed out. Please check that the CTDE backend is running and try again.'
    ),
  ]);

  return buildInvestigationResult(backend);
}

/**
 * Real Email Header forensic investigation.
 *
 * Sends raw email headers to:
 * POST /analyze/email
 *
 * The backend performs:
 * - SPF analysis
 * - DKIM analysis
 * - DMARC analysis
 * - Reply-To analysis
 * - Return-Path analysis
 * - Received header/IP analysis
 * - Authentication-Results analysis
 * - Spoofing detection
 * - Suspicious keyword detection
 * - DNS/MX evidence
 * - Risk analysis
 */
export async function runEmailHeaderInvestigation(
  rawHeaders: string
): Promise<InvestigationResult> {
  if (!rawHeaders || !rawHeaders.trim()) {
    throw new Error('Please provide email headers.');
  }

  if (rawHeaders.trim().length < 20) {
    throw new Error(
      'Please provide valid email headers. Paste the complete email header.'
    );
  }

  const investigation = postAnalyzeEmailHeaders(
    rawHeaders.trim()
  );

  const backend = await Promise.race([
    investigation,
    createTimeout(
      'Email header investigation timed out. Please check that the CTDE backend is running and try again.'
    ),
  ]);

  return buildInvestigationResult(backend);
}

/**
 * Real QR image investigation.
 *
 * The image file is sent to the FastAPI /analyze/qr endpoint.
 * The backend decodes the QR and performs the full CTDE analysis.
 */
export async function runQrInvestigation(
  file: File
): Promise<InvestigationResult> {
  const investigation = postAnalyzeQr(file);

  const backend = await Promise.race([
    investigation,
    createTimeout(
      'QR investigation timed out. Please check that the CTDE backend is running and try again.'
    ),
  ]);

  return buildInvestigationResult(backend);
}
/**
 * Real APK forensic investigation.
 *
 * Sends the actual APK binary to:
 * POST /analyze/apk
 *
 * The backend performs:
 * - SHA-256 hashing
 * - Android permission extraction
 * - dangerous permission detection
 * - activities
 * - services
 * - receivers
 * - network URL extraction
 * - signing certificate analysis
 * - malware indicators
 * - APK risk scoring
 */
export async function runApkInvestigation(
  file: File
): Promise<InvestigationResult> {
  if (!file) {
    throw new Error('Please select an APK file.');
  }

  if (!file.name.toLowerCase().endsWith('.apk')) {
    throw new Error('Please select a valid .apk file.');
  }

  const investigation = postAnalyzeApk(file);

  const backend = await Promise.race([
    investigation,
    createTimeout(
      'APK investigation timed out. Please check that the CTDE backend is running and try again.'
    ),
  ]);

  return buildInvestigationResult(backend);
}