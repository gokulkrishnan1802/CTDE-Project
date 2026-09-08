export interface User {
  id: string;
  fullName: string;
  email: string;
  username: string;
  password: string;
  createdAt: string;
}

export type EvidenceType =
  | 'url'
  | 'email'
  | 'apk'
  | 'qr'
  | 'sender';

export type RiskLevel =
  | 'Safe'
  | 'Suspicious'
  | 'Dangerous';

export interface TimelineEvent {
  label: string;
  timestamp: string;
  status: 'done' | 'active' | 'pending';
}

export interface EvidencePanel {
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

export interface QRAnalysis {
  decodedUrl: string;
  redirects: string[];
  reputation: string;
  qrRiskLevel: string;
}

export interface Investigation {
  id: string;
  caseId: string;
  userId: string;
  caseName: string;
  caseDescription: string;
  evidenceType: EvidenceType;
  evidenceValue: string;
  trustScore: number;
  riskLevel: RiskLevel;
  report: string;
  createdAt: string;
  investigator: string;
  aiConfidence: number;
  evidencePanel: EvidencePanel;
  timeline: TimelineEvent[];
  analysis: AnalysisResult;
}

export interface AnalysisResult {
  evidenceSummary: string;
  identityVerification: string;
  domainVerification: string;
  certificateValidation: string;
  whoisInfo: string;
  brandImpersonation: string;
  urlAnalysis: string;

  apkPermissionAnalysis?: string;
    apk?: {
    sha256: string;
    permissions: string[];
    dangerousPermissions: string[];
    receivers: string[];
    services: string[];
    activities: string[];
    malwareDetection: string;
    riskScore: number;
  };
  senderVerification?: string;
  qrVerification?: string;

  // Structured QR investigation data
  qr?: QRAnalysis;

  reputationAnalysis: string;

  trustScore: number;
  riskLevel: RiskLevel;

  reasonBehindDecision: string;
  investigationStory: string;

  mitreMapping: string[];

  aiSummary: string;
  aiExplanation: string;

  recommendations: string[];

  scoreBreakdown?: ScoreBreakdown[];

  email?: {
  spf: string;
  dkim: string;
  dmarc: string;
  replyToAnalysis: string;
  senderDomain: string;
  spoofDetection: string;
};
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface ScoreBreakdown {
  label: string;
  positive: boolean;
  points: number;
}