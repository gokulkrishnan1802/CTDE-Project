/** Deterministic trust score calculator. Never generates random scores. */

import type { WhoisResult } from './whoisLookup';
import type { SSLResult } from './sslCheck';
import type { DNSResult } from './dnsLookup';
import type { URLAnalysisResult } from './urlAnalyzer';
import type { BrandResult } from './brandDetector';
import type { EmailAnalysisResult } from './emailAnalyzer';

export interface ScoreFactor {
  label: string;
  positive: boolean;
  points: number;
}

export interface RiskScore {
  score: number;
  riskLevel: 'Safe' | 'Suspicious' | 'Dangerous';
  factors: ScoreFactor[];
  confidence: number;
}

function clamp(n: number): number { return Math.max(0, Math.min(100, n)); }

export function scoreToRiskLevel(score: number): 'Safe' | 'Suspicious' | 'Dangerous' {
  if (score <= 40) return 'Dangerous';
  if (score <= 60) return 'Suspicious';
  return 'Safe';
}

// ── URL / Website ─────────────────────────────────────────────────────────────

export interface URLEvidenceInput {
  whois: WhoisResult;
  ssl: SSLResult;
  dns: DNSResult;
  urlAnalysis: URLAnalysisResult;
  brand: BrandResult;
  securityHeaders?: Record<string, string>;
}

export function scoreURL(ev: URLEvidenceInput): RiskScore {
  const factors: ScoreFactor[] = [];
  let score = 60; // neutral baseline

  // ── Domain age ────────────────────────────────────────────────────────────
  const ageDays = ev.whois.domainAgeDays;
  if (ageDays !== null) {
    if (ageDays >= 365 * 5) {
      score += 15; factors.push({ label: 'Established domain (5+ years old)', positive: true, points: 15 });
    } else if (ageDays >= 365 * 2) {
      score += 8; factors.push({ label: 'Moderately aged domain (2+ years)', positive: true, points: 8 });
    } else if (ageDays >= 365) {
      score += 3; factors.push({ label: 'Young domain (1–2 years)', positive: true, points: 3 });
    } else if (ageDays >= 90) {
      score -= 10; factors.push({ label: 'Recently registered domain (< 12 months)', positive: false, points: -10 });
    } else if (ageDays >= 30) {
      score -= 20; factors.push({ label: 'Very newly registered domain (< 3 months)', positive: false, points: -20 });
    } else {
      score -= 30; factors.push({ label: `Brand-new domain — registered only ${ageDays} day(s) ago`, positive: false, points: -30 });
    }
  } else if (ev.whois.registrar === 'Lookup failed') {
    factors.push({ label: 'WHOIS lookup failed — age unknown', positive: false, points: 0 });
  }

  // ── SSL ───────────────────────────────────────────────────────────────────
  if (ev.ssl.isValid) {
    score += 15; factors.push({ label: 'Valid TLS/SSL certificate', positive: true, points: 15 });
  } else if (ev.ssl.sslStatus.includes('timed out')) {
    factors.push({ label: 'SSL probe timed out — could not verify certificate', positive: false, points: 0 });
  } else {
    score -= 20; factors.push({ label: 'No valid SSL certificate / HTTPS unavailable', positive: false, points: -20 });
  }

  // ── HTTPS ─────────────────────────────────────────────────────────────────
  if (!ev.urlAnalysis.httpsStatus) {
    score -= 10; factors.push({ label: 'Plain HTTP — no encryption', positive: false, points: -10 });
  }

  // ── DNS resolution ────────────────────────────────────────────────────────
  if (ev.dns.aRecord.length > 0) {
    factors.push({ label: `Domain resolves correctly (IP: ${ev.dns.aRecord[0]})`, positive: true, points: 0 });
  } else {
    score -= 10; factors.push({ label: 'Domain does not resolve — no DNS A record', positive: false, points: -10 });
  }

  // ── Brand impersonation ───────────────────────────────────────────────────
  if (ev.brand.brandName !== 'None' && !ev.brand.isOfficialDomain && ev.brand.confidence > 60) {
    score -= 25;
    factors.push({ label: `Brand impersonation: ${ev.brand.brandName} (${ev.brand.confidence}% confidence)`, positive: false, points: -25 });
  } else if (ev.brand.brandName === 'None') {
    score += 10; factors.push({ label: 'No brand impersonation detected', positive: true, points: 10 });
  } else if (ev.brand.isOfficialDomain) {
    score += 5; factors.push({ label: `Official ${ev.brand.brandName} domain confirmed`, positive: true, points: 5 });
  }

  // ── URL structure ─────────────────────────────────────────────────────────
  if (ev.urlAnalysis.ipAddressDetection) {
    score -= 15; factors.push({ label: 'Raw IP address used in URL — no domain name', positive: false, points: -15 });
  }
  if (ev.urlAnalysis.isSuspiciousTLD) {
    score -= 10; factors.push({ label: `Suspicious free TLD (.${ev.urlAnalysis.tld})`, positive: false, points: -10 });
  }
  if (ev.urlAnalysis.encodedCharacters) {
    score -= 5; factors.push({ label: 'URL contains encoded/obfuscated characters', positive: false, points: -5 });
  }
  if (ev.urlAnalysis.suspiciousParameters.length > 0) {
    score -= 8; factors.push({ label: `Suspicious URL parameters: ${ev.urlAnalysis.suspiciousParameters.join(', ')}`, positive: false, points: -8 });
  }
  if (ev.urlAnalysis.punycode) {
    score -= 10; factors.push({ label: 'Punycode/IDN domain — potential homograph attack', positive: false, points: -10 });
  }
  if (ev.urlAnalysis.hasExcessiveSubdomains) {
    score -= 8; factors.push({ label: 'Excessive subdomains — common in phishing', positive: false, points: -8 });
  }
  if (ev.urlAnalysis.suspiciousKeywords.length > 0) {
    const penalty = Math.min(ev.urlAnalysis.suspiciousKeywords.length * 5, 20);
    score -= penalty; factors.push({ label: `Suspicious keywords in URL: ${ev.urlAnalysis.suspiciousKeywords.slice(0, 3).join(', ')}`, positive: false, points: -penalty });
  }
  if (ev.urlAnalysis.urlLength > 100) {
    score -= 5; factors.push({ label: `Unusually long URL (${ev.urlAnalysis.urlLength} chars)`, positive: false, points: -5 });
  }

  // ── Security headers ──────────────────────────────────────────────────────
  if (ev.securityHeaders) {
    const present = Object.values(ev.securityHeaders).filter(v => v !== 'MISSING').length;
    const total = Object.keys(ev.securityHeaders).length;
    if (present >= Math.floor(total * 0.7)) {
      score += 8; factors.push({ label: `Good security headers (${present}/${total} present)`, positive: true, points: 8 });
    } else if (present <= 1) {
      score -= 5; factors.push({ label: `Poor security headers (${present}/${total} present)`, positive: false, points: -5 });
    }
  }

  const finalScore = clamp(score);
  return { score: finalScore, riskLevel: scoreToRiskLevel(finalScore), factors, confidence: 88 };
}

// ── Email ─────────────────────────────────────────────────────────────────────

export interface EmailEvidenceInput {
  emailData: EmailAnalysisResult;
}

export function scoreEmail(ev: EmailEvidenceInput): RiskScore {
  const factors: ScoreFactor[] = [];
  let score = 60;
  const d = ev.emailData;

  if (d.spf.startsWith('Pass')) {
    score += 15; factors.push({ label: 'SPF record valid', positive: true, points: 15 });
  } else if (d.spf.startsWith('Weak')) {
    score += 3; factors.push({ label: 'SPF present but uses soft-fail', positive: false, points: 3 });
  } else {
    score -= 15; factors.push({ label: 'SPF record missing — spoofing risk', positive: false, points: -15 });
  }

  if (d.dkim.startsWith('Pass')) {
    score += 15; factors.push({ label: 'DKIM key found', positive: true, points: 15 });
  } else {
    factors.push({ label: 'DKIM not verified (requires raw email headers)', positive: false, points: 0 });
  }

  if (d.dmarc.startsWith('Pass')) {
    score += 10; factors.push({ label: `DMARC configured (policy: ${d.dmarcPolicy})`, positive: true, points: 10 });
    if (d.dmarcPolicy === 'reject') { score += 5; factors.push({ label: 'DMARC reject policy — strict protection', positive: true, points: 5 }); }
  } else if (d.dmarc.startsWith('Weak')) {
    score -= 5; factors.push({ label: 'DMARC policy is "none" — no enforcement', positive: false, points: -5 });
  } else {
    score -= 10; factors.push({ label: 'DMARC record missing', positive: false, points: -10 });
  }

  if (d.spoofDetection.startsWith('Potential')) {
    score -= 20; factors.push({ label: d.spoofDetection, positive: false, points: -20 });
  } else {
    factors.push({ label: 'No spoofing indicators detected', positive: true, points: 0 });
  }

  if (d.isFreemail) {
    score -= 5; factors.push({ label: 'Free email provider — low identity assurance', positive: false, points: -5 });
  }
  if (!d.mxExists) {
    score -= 15; factors.push({ label: 'No MX records — domain cannot receive email', positive: false, points: -15 });
  }
  if (d.suspiciousKeywords.length > 0) {
    const penalty = Math.min(d.suspiciousKeywords.length * 5, 20);
    score -= penalty; factors.push({ label: `Suspicious keywords in address: ${d.suspiciousKeywords.slice(0, 3).join(', ')}`, positive: false, points: -penalty });
  }

  const finalScore = clamp(score);
  return { score: finalScore, riskLevel: scoreToRiskLevel(finalScore), factors, confidence: 85 };
}

// ── QR ────────────────────────────────────────────────────────────────────────

export function scoreQR(riskIndicators: string[], baseScore?: number): RiskScore {
  let score = baseScore ?? 60;
  const factors: ScoreFactor[] = [];

  for (const ind of riskIndicators) {
    score -= 10; factors.push({ label: `QR risk indicator: ${ind}`, positive: false, points: -10 });
  }
  if (riskIndicators.length === 0) {
    score += 5; factors.push({ label: 'No QR-specific risk indicators detected', positive: true, points: 5 });
  }

  const finalScore = clamp(score);
  return { score: finalScore, riskLevel: scoreToRiskLevel(finalScore), factors, confidence: 80 };
}

// ── APK ───────────────────────────────────────────────────────────────────────

export function scoreAPK(dangerousPerms: string[], malwareFlags: string[]): RiskScore {
  const factors: ScoreFactor[] = [];
  let score = 80; // start optimistic

  const permPenalty = Math.min(dangerousPerms.length * 6, 40);
  if (permPenalty > 0) {
    score -= permPenalty;
    factors.push({ label: `${dangerousPerms.length} dangerous permission(s) declared`, positive: false, points: -permPenalty });
  }
  const malwarePenalty = Math.min(malwareFlags.length * 15, 45);
  if (malwarePenalty > 0) {
    score -= malwarePenalty;
    for (const f of malwareFlags.slice(0, 4)) {
      factors.push({ label: `Malware indicator: ${f}`, positive: false, points: -15 });
    }
  }
  if (malwareFlags.length === 0 && dangerousPerms.length < 4) {
    factors.push({ label: 'No high-severity malware indicators detected', positive: true, points: 0 });
  }

  const finalScore = clamp(score);
  return { score: finalScore, riskLevel: scoreToRiskLevel(finalScore), factors, confidence: 75 };
}
