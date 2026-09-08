import type {
  AnalysisResult,
  EvidencePanel,
  RiskLevel,
  ScoreBreakdown,
} from '../types';

export const API_BASE_URL = 'https://cyberverify-ai.onrender.com';

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  let res: Response;

  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      ...options,
    });
  } catch {
    throw new ApiError(
      'Unable to reach the CTDE analysis backend. Please ensure the server is running.'
    );
  }

  if (!res.ok) {
    let detail = `Request failed (${res.status})`;

    try {
      const body = await res.json();

      if (body?.detail) {
        detail =
          typeof body.detail === 'string'
            ? body.detail
            : JSON.stringify(body.detail);
      }
    } catch {
      // Keep default error.
    }

    throw new ApiError(detail, res.status);
  }

  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────────
// Authentication
// ─────────────────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  full_name: string;
  email: string;
  username: string;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}

export interface RegisterRequest {
  full_name: string;
  email: string;
  username: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

const AUTH_TOKEN_KEY = 'cyberverify_access_token';

export function getAuthToken(): string | null {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

export function saveAuthToken(token: string): void {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  localStorage.removeItem(AUTH_TOKEN_KEY);
}

export async function registerUser(
  payload: RegisterRequest
): Promise<AuthResponse> {
  return request<AuthResponse>('/users/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function loginUser(
  payload: LoginRequest
): Promise<AuthResponse> {
  return request<AuthResponse>('/users/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getCurrentUser(): Promise<AuthUser> {
  const token = getAuthToken();

  if (!token) {
    throw new ApiError('No authentication token found.', 401);
  }

  return request<AuthUser>('/users/me', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });
}

// ─────────────────────────────────────────────────────────────
// Backend response types
// ─────────────────────────────────────────────────────────────

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
  overall: 'malicious' | 'suspicious' | 'clean' | string;
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
  registrar:
    | string
    | {
        name?: string;
        ianaId?: string;
        url?: string;
        whoisServer?: string;
        abuseEmail?: string;
        abusePhone?: string;
        reseller?: string;
      };
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

// ─────────────────────────────────────────────────────────────
// Standard analysis
// ─────────────────────────────────────────────────────────────

export interface AnalyzeRequest {
  evidenceType: string;
  evidenceValue: string;
}

export async function postAnalyze(
  payload: AnalyzeRequest
): Promise<BackendAnalysisResponse> {
  return request<BackendAnalysisResponse>('/analyze', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ─────────────────────────────────────────────────────────────
// EMAIL HEADER ANALYSIS
// ─────────────────────────────────────────────────────────────

export interface EmailHeaderRequest {
  rawHeaders: string;
}

export async function postAnalyzeEmailHeaders(
  rawHeaders: string
): Promise<BackendAnalysisResponse> {
  if (!rawHeaders || !rawHeaders.trim()) {
    throw new ApiError('Please provide email headers.');
  }

  return request<BackendAnalysisResponse>('/analyze/email', {
    method: 'POST',
    body: JSON.stringify({
      rawHeaders: rawHeaders.trim(),
    }),
  });
}

// ─────────────────────────────────────────────────────────────
// AI Assistant
// ─────────────────────────────────────────────────────────────

export interface AskAIRequest {
  question: string;
  investigation: AnalysisResult & {
    evidenceType: string;
    evidenceValue: string;
    caseId: string;
  };
}

export interface AskAIResponse {
  answer: string;
}

export async function postAskAI(
  payload: AskAIRequest
): Promise<AskAIResponse> {
  return request<AskAIResponse>('/ask-ai', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ─────────────────────────────────────────────────────────────
// Backend → Frontend mapping
// ─────────────────────────────────────────────────────────────

export function mapBackendResponse(
  res: BackendAnalysisResponse
): {
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

    registrar:
      typeof res.evidencePanel.registrar === 'string'
        ? res.evidencePanel.registrar
        : res.evidencePanel.registrar?.name || 'Unknown',

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

    scoreBreakdown: res.scoreBreakdown?.map(
      (factor): ScoreBreakdown => ({
        label: factor.label,
        positive: factor.positive,
        points: factor.points,
      })
    ),

    // ─────────────────────────────────────────────
    // EMAIL STRUCTURED DATA
    // ─────────────────────────────────────────────

    email: res.email
      ? {
          spf: res.email.spf || 'Unknown',
          dkim: res.email.dkim || 'Unknown',
          dmarc: res.email.dmarc || 'Unknown',
          replyToAnalysis:
            res.email.replyToAnalysis || 'No Reply-To analysis available',
          senderDomain:
            res.email.senderDomain || 'Unknown',
          spoofDetection:
            res.email.spoofDetection ||
            'No spoofing information available',
        }
      : undefined,

    // ─────────────────────────────────────────────
    // QR STRUCTURED DATA
    // ─────────────────────────────────────────────

    qr: res.qr
      ? {
          decodedUrl: res.qr.decodedUrl || '',
          redirects: res.qr.redirects || [],
          reputation: res.qr.reputation || 'Unknown',
          qrRiskLevel: res.qr.qrRiskLevel || 'Unknown',
        }
      : undefined,

    // ─────────────────────────────────────────────
    // APK STRUCTURED DATA
    // ─────────────────────────────────────────────

    apk: res.apk
      ? {
          sha256: res.apk.sha256 || '',
          permissions: res.apk.permissions || [],
          dangerousPermissions:
            res.apk.dangerousPermissions || [],
          receivers: res.apk.receivers || [],
          services: res.apk.services || [],
          activities: res.apk.activities || [],
          malwareDetection:
            res.apk.malwareDetection || 'Unknown',
          riskScore: res.apk.riskScore ?? 0,
        }
      : undefined,
  };

  return {
    analysis,
    evidencePanel,
    aiConfidence: res.confidence,
  };
}

// ─────────────────────────────────────────────────────────────
// QR IMAGE ANALYSIS
// ─────────────────────────────────────────────────────────────

export async function postAnalyzeQr(
  file: File
): Promise<BackendAnalysisResponse> {
  const formData = new FormData();

  formData.append('file', file);

  let response: Response;

  try {
    response = await fetch(
      `${API_BASE_URL}/analyze/qr`,
      {
        method: 'POST',
        body: formData,
      }
    );
  } catch {
    throw new ApiError(
      'Unable to reach the CTDE analysis backend.'
    );
  }

  if (!response.ok) {
    let message = 'QR analysis failed.';

    try {
      const data = await response.json();

      if (data?.detail) {
        message =
          typeof data.detail === 'string'
            ? data.detail
            : JSON.stringify(data.detail);
      }
    } catch {
      // Keep default message.
    }

    throw new ApiError(message, response.status);
  }

  return response.json();
}