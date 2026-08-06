import type { AnalysisResult, EvidencePanel, RiskLevel } from '../types';

export const API_BASE_URL = 'http://localhost:8000';

export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
  } catch {
    throw new ApiError('Unable to reach the CTDE analysis backend. Please ensure the server is running.');
  }
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch { /* ignore */ }
    throw new ApiError(detail, res.status);
  }
  return res.json() as Promise<T>;
}

export interface BackendScoreBreakdown {
  label: string;
  positive: boolean;
  points: number;
}

export interface BackendMitreTechnique {
  techniqueId: string;
  techniqueName: string;
  description: string;
}

export interface BackendWhois {
  registrar: string;
  registrationDate: string;
  expiryDate: string;
  domainAge: string;
  country: string;
  whoisStatus: string;
}

export interface BackendSSL {
  sslStatus: string;
  tlsVersion: string;
  issuer: string;
  validFrom: string;
  validUntil: string;
  certificateChain: string;
  subject: string;
  san: string[];
}

export interface BackendDNS {
  aRecord: string[];
  aaaaRecord: string[];
  mx: string[];
  txt: string[];
  ns: string[];
  cname: string[];
}

export interface BackendReputation {
  virusTotal: string;
  urlScan: string;
  phishTank: string;
  abuseIpdb: string;
  googleSafeBrowsing: string;
  vendorCount: number;
  detectionRatio: string;
  overall: 'malicious' | 'suspicious' | 'clean';
}

export interface BackendBrand {
  brandName: string;
  confidence: number;
  evidence: string;
  visualSimilarity: number;
  domainSimilarity: number;
}

export interface BackendURLAnalysis {
  redirectCount: number;
  urlLength: number;
  encodedCharacters: boolean;
  suspiciousParameters: string[];
  ipAddressDetection: boolean;
  httpsStatus: boolean;
}

export interface BackendQR {
  decodedUrl: string;
  redirects: string[];
  reputation: string;
  qrRiskLevel: string;
}

export interface BackendEmail {
  spf: string;
  dkim: string;
  dmarc: string;
  replyToAnalysis: string;
  senderDomain: string;
  spoofDetection: string;
}

export interface BackendAPK {
  sha256: string;
  permissions: string[];
  dangerousPermissions: string[];
  receivers: string[];
  services: string[];
  activities: string[];
  malwareDetection: string;
  riskScore: number;
}

export interface BackendEvidencePanel {
  originalUrl: string;
  resolvedUrl: string;
  ipAddress: string;
  hostingProvider: string;
  country: string;
  registrar: string;
  sslStatus: string;
  whoisStatus: string;
  sha256Hash: string;
}

export interface BackendAnalysisResponse {
  evidenceType: string;
  evidenceValue: string;
  evidenceSummary: string;
  identityVerification: string;
  domainVerification: string;
  certificateValidation: string;
  whoisInfo: string;
  brandImpersonation: string;
  urlAnalysis: string;
  apkPermissionAnalysis?: string;
  senderVerification?: string;
  qrVerification?: string;
  reputationAnalysis: string;
  trustScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  reasonBehindDecision: string;
  investigationStory: string;
  mitreMapping: string[];
  aiSummary: string;
  aiExplanation: string;
  recommendations: string[];
  scoreBreakdown?: BackendScoreBreakdown[];
  mitreTechniques?: BackendMitreTechnique[];
  whois?: BackendWhois;
  ssl?: BackendSSL;
  dns?: BackendDNS;
  reputation?: BackendReputation;
  brand?: BackendBrand;
  urlAnalysisStructured?: BackendURLAnalysis;
  qr?: BackendQR;
  email?: BackendEmail;
  apk?: BackendAPK;
  evidencePanel: BackendEvidencePanel;
}

export interface AnalyzeRequest {
  evidenceType: string;
  evidenceValue: string;
}

export async function postAnalyze(payload: AnalyzeRequest): Promise<BackendAnalysisResponse> {
  return request<BackendAnalysisResponse>('/analyze', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export interface AskAIRequest {
  question: string;
  investigation: AnalysisResult & { evidenceType: string; evidenceValue: string; caseId: string };
}

export interface AskAIResponse {
  answer: string;
}

export async function postAskAI(payload: AskAIRequest): Promise<AskAIResponse> {
  return request<AskAIResponse>('/ask-ai', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function mapBackendResponse(res: BackendAnalysisResponse): {
  analysis: AnalysisResult;
  evidencePanel: EvidencePanel;
  aiConfidence: number;
} {
  const evidencePanel: EvidencePanel = {
    originalUrl: res.evidencePanel.originalUrl,
    resolvedUrl: res.evidencePanel.resolvedUrl,
    ipAddress: res.evidencePanel.ipAddress,
    hostingProvider: res.evidencePanel.hostingProvider,
    country: res.evidencePanel.country,
    registrar: res.evidencePanel.registrar,
    sslStatus: res.evidencePanel.sslStatus,
    whoisStatus: res.evidencePanel.whoisStatus,
    sha256Hash: res.evidencePanel.sha256Hash,
  };

  const analysis: AnalysisResult = {
    evidenceSummary: res.evidenceSummary,
    identityVerification: res.identityVerification,
    domainVerification: res.domainVerification,
    certificateValidation: res.certificateValidation,
    whoisInfo: res.whoisInfo,
    brandImpersonation: res.brandImpersonation,
    urlAnalysis: res.urlAnalysis,
    apkPermissionAnalysis: res.apkPermissionAnalysis,
    senderVerification: res.senderVerification,
    qrVerification: res.qrVerification,
    reputationAnalysis: res.reputationAnalysis,
    trustScore: res.trustScore,
    riskLevel: res.riskLevel,
    reasonBehindDecision: res.reasonBehindDecision,
    investigationStory: res.investigationStory,
    mitreMapping: res.mitreMapping,
    aiSummary: res.aiSummary,
    aiExplanation: res.aiExplanation,
    recommendations: res.recommendations,
  };

  return { analysis, evidencePanel, aiConfidence: res.confidence };
}
