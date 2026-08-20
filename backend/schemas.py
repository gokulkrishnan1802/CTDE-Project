from __future__ import annotations
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, field_validator


# ── Auth ──────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    full_name: str
    email: EmailStr
    username: str
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    full_name: str
    email: str
    username: str
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")

        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain an uppercase letter")

        if not any(c.islower() for c in v):
            raise ValueError("Password must contain a lowercase letter")

        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain a number")

        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain a special character")

        return v
# ── Investigation Request ─────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    evidenceType: str  # url | email | apk | qr | sender
    evidenceValue: str

    @field_validator("evidenceType")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"url", "email", "apk", "qr", "sender"}
        if v not in allowed:
            raise ValueError(f"evidenceType must be one of {allowed}")
        return v


class AskAIRequest(BaseModel):
    question: str
    investigation: dict[str, Any]


class AskAIResponse(BaseModel):
    answer: str


# ── Structured sub-objects ────────────────────────────────────────────────────

class ScoreBreakdown(BaseModel):
    label: str
    positive: bool
    points: int


class MitreTechnique(BaseModel):
    techniqueId: str
    techniqueName: str
    description: str


class WhoisData(BaseModel):
    registrar: str
    registrationDate: str
    expiryDate: str
    domainAge: str
    country: str
    whoisStatus: str


class SSLData(BaseModel):
    sslStatus: str
    tlsVersion: str
    issuer: str
    validFrom: str
    validUntil: str
    certificateChain: str
    subject: str
    san: List[str]


class DNSData(BaseModel):
    aRecord: List[str]
    aaaaRecord: List[str]
    mx: List[str]
    txt: List[str]
    ns: List[str]
    cname: List[str]


class ReputationData(BaseModel):
    virusTotal: str
    urlScan: str
    phishTank: str
    abuseIpdb: str
    googleSafeBrowsing: str
    vendorCount: int
    detectionRatio: str
    overall: str  # malicious | suspicious | clean


class BrandData(BaseModel):
    brandName: str
    confidence: float
    evidence: str
    visualSimilarity: float
    domainSimilarity: float


class URLAnalysisData(BaseModel):
    redirectCount: int
    urlLength: int
    encodedCharacters: bool
    suspiciousParameters: List[str]
    ipAddressDetection: bool
    httpsStatus: bool


class QRData(BaseModel):
    decodedUrl: str
    redirects: List[str]
    reputation: str
    qrRiskLevel: str


class EmailData(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    replyToAnalysis: str
    senderDomain: str
    spoofDetection: str


class APKData(BaseModel):
    sha256: str
    permissions: List[str]
    dangerousPermissions: List[str]
    receivers: List[str]
    services: List[str]
    activities: List[str]
    malwareDetection: str
    riskScore: int


class EvidencePanelData(BaseModel):
    originalUrl: str
    resolvedUrl: str
    ipAddress: str
    hostingProvider: str
    country: str
    registrar: str
    sslStatus: str
    whoisStatus: str
    sha256Hash: str


# ── Main Analysis Response ────────────────────────────────────────────────────

class AnalysisResponse(BaseModel):
    evidenceType: str
    evidenceValue: str
    evidenceSummary: str
    identityVerification: str
    domainVerification: str
    certificateValidation: str
    whoisInfo: str
    brandImpersonation: str
    urlAnalysis: str
    apkPermissionAnalysis: Optional[str] = None
    senderVerification: Optional[str] = None
    qrVerification: Optional[str] = None
    reputationAnalysis: str
    trustScore: int
    riskLevel: str  # Safe | Suspicious | Dangerous
    confidence: int
    reasonBehindDecision: str
    investigationStory: str
    mitreMapping: List[str]
    aiSummary: str
    aiExplanation: str
    recommendations: List[str]
    scoreBreakdown: Optional[List[ScoreBreakdown]] = None
    mitreTechniques: Optional[List[MitreTechnique]] = None
    whois: Optional[WhoisData] = None
    ssl: Optional[SSLData] = None
    dns: Optional[DNSData] = None
    reputation: Optional[ReputationData] = None
    brand: Optional[BrandData] = None
    urlAnalysisStructured: Optional[URLAnalysisData] = None
    qr: Optional[QRData] = None
    email: Optional[EmailData] = None
    apk: Optional[APKData] = None
    evidencePanel: EvidencePanelData


# ── Report Schemas ────────────────────────────────────────────────────────────

class ReportOut(BaseModel):
    id: str
    investigation_id: str
    user_id: str
    report_type: str
    file_path: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
