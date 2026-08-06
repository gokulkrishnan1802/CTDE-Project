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

export type RiskLevel = 'Safe' | 'Suspicious' | 'Dangerous';

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
  senderVerification?: string;
  qrVerification?: string;
  reputationAnalysis: string;
  trustScore: number;
  riskLevel: RiskLevel;
  reasonBehindDecision: string;
  investigationStory: string;
  mitreMapping: string[];
  aiSummary: string;
  aiExplanation: string;
  recommendations: string[];
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}
