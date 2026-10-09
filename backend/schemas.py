from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Auth ──────────────────────────────────────────────────────────────────────

def validate_password_strength(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not any(char.isupper() for char in value):
        raise ValueError("Password must contain an uppercase letter")
    if not any(char.islower() for char in value):
        raise ValueError("Password must contain a lowercase letter")
    if not any(char.isdigit() for char in value):
        raise ValueError("Password must contain a number")
    if not any(not char.isalnum() for char in value):
        raise ValueError("Password must contain a special character")
    return value


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)


class UserRegister(BaseModel):
    full_name: str
    email: EmailStr
    username: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)


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


# ── Investigation Request ────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    evidenceType: str
    evidenceValue: str

    @field_validator("evidenceType", mode="before")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("evidenceType must be a string")

        value = value.strip().lower()
        allowed = {"url", "email", "apk", "qr", "sender"}

        if value not in allowed:
            raise ValueError(
                f"evidenceType must be one of: {', '.join(sorted(allowed))}"
            )
        return value

    @field_validator("evidenceValue")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("evidenceValue must be a string")

        value = value.strip()
        if not value:
            raise ValueError("evidenceValue cannot be empty")
        if len(value) > 10000:
            raise ValueError(
                "evidenceValue is too large. Maximum length is 10000 characters."
            )
        return value


class EmailHeaderRequest(BaseModel):
    rawHeaders: str

    @field_validator("rawHeaders")
    @classmethod
    def validate_raw_headers(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Email headers cannot be empty")
        if len(value.strip()) < 20:
            raise ValueError("Please provide valid email headers")
        return value.strip()


class AskAIRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    investigation: dict[str, Any]


class AskAIResponse(BaseModel):
    answer: str


# ── Structured sub-objects ───────────────────────────────────────────────────

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


# ── Main Analysis Response ───────────────────────────────────────────────────

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
    confidence: Optional[int] = None
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
    digitalEvidence: Optional[dict] = None
    # Module 5 — Evidence Processing & Correlation
    evidenceProcessing: Optional[dict] = None


# ── Report Schemas ───────────────────────────────────────────────────────────

class ReportOut(BaseModel):
    id: str
    investigation_id: str
    user_id: str
    report_type: str
    file_path: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class GoogleLoginRequest(BaseModel):
    credential: str