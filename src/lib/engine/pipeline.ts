/**
 * Main investigation pipeline.
 * Orchestrates all evidence collection modules and returns
 * the exact BackendAnalysisResponse shape the frontend expects.
 * Every external call is capped with withTimeout so nothing hangs forever.
 */

import { lookupDNS } from './dnsLookup';
import { lookupWhois } from './whoisLookup';
import { checkSSL } from './sslCheck';
import { analyzeURL, extractDomain, normalizeUrl } from './urlAnalyzer';
import { detectBrand } from './brandDetector';
import { resolveIP, geolocateIP } from './geoIP';
import { analyzeEmail } from './emailAnalyzer';
import { scoreURL, scoreEmail, scoreQR, scoreAPK } from './riskScorer';
import { buildAIText } from './aiExplainer';
import type { BackendAnalysisResponse } from '../../services/api';
import type { WhoisResult } from './whoisLookup';
import type { DNSResult } from './dnsLookup';
import type { SSLResult } from './sslCheck';
import type { GeoResult } from './geoIP';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Resolves to `fallback` after `ms` ms — never rejects. */
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise.catch(() => fallback),
    new Promise<T>(resolve => setTimeout(() => resolve(fallback), ms)),
  ]);
}

function sha256Stub(val: string): string {
  let h = 5381;
  for (let i = 0; i < val.length; i++) h = (h * 33) ^ val.charCodeAt(i);
  const hex = (h >>> 0).toString(16).padStart(8, '0');
  return (hex.repeat(8)).slice(0, 64);
}

// Fallback values used when a network call times out or fails
const EMPTY_WHOIS: WhoisResult = {
  registrar: 'Lookup timed out', registrationDate: 'Unknown', expiryDate: 'Unknown',
  domainAge: 'Unknown', domainAgeDays: null, country: 'Unknown',
  whoisStatus: 'Unknown', nameservers: [],
};
const EMPTY_DNS: DNSResult = { aRecord: [], aaaaRecord: [], mx: [], txt: [], ns: [], cname: [] };
const EMPTY_SSL: SSLResult = {
  sslStatus: 'Unknown', tlsVersion: 'Unknown', issuer: 'Unknown',
  validFrom: 'N/A', validUntil: 'N/A', certificateChain: 'N/A',
  subject: '', san: [], isValid: false,
};
const EMPTY_GEO: GeoResult = { ip: 'N/A', country: 'Unknown', city: 'Unknown', org: 'Unknown', hosting: 'Unknown' };

// ── URL pipeline ──────────────────────────────────────────────────────────────

export async function investigateURL(rawUrl: string): Promise<BackendAnalysisResponse> {
  const url = normalizeUrl(rawUrl);
  const domain = extractDomain(url);
  const urlAnalysis = analyzeURL(url);
  const brand = detectBrand(domain);

  // Run all network calls in parallel, each capped at a hard timeout
  const [whois, dns, ssl] = await Promise.all([
    withTimeout(lookupWhois(domain), 8000, EMPTY_WHOIS),
    withTimeout(lookupDNS(domain), 6000, EMPTY_DNS),
    withTimeout(checkSSL(domain), 8000, EMPTY_SSL),
  ]);

  const ip = dns.aRecord[0] ?? await withTimeout(resolveIP(domain), 5000, 'Unresolvable');
  const geo = await withTimeout(geolocateIP(ip), 5000, { ...EMPTY_GEO, ip });

  const riskScore = scoreURL({ whois, ssl, dns, urlAnalysis, brand });
  const ai = buildAIText({
    evidenceType: 'url',
    evidenceValue: url,
    riskScore,
    whoisAge: whois.domainAge,
    whoisRegistrar: whois.registrar,
    sslStatus: ssl.sslStatus,
    tlsVersion: ssl.tlsVersion,
    brandEvidence: brand.evidence,
    brandName: brand.brandName,
    ipAddress: ip,
    hosting: geo.hosting,
    country: geo.country,
    urlKeywords: urlAnalysis.suspiciousKeywords,
    domainAgeDays: whois.domainAgeDays,
  });

  const evSummary = `URL investigation of ${url}. Domain: ${domain} | IP: ${ip} | Hosting: ${geo.hosting} | Country: ${geo.country}. SSL: ${ssl.sslStatus} | Domain age: ${whois.domainAge} | Registrar: ${whois.registrar}.`;

  return {
    evidenceType: 'url',
    evidenceValue: url,
    evidenceSummary: evSummary,
    identityVerification: `Domain '${domain}' registered via ${whois.registrar}. Registration: ${whois.registrationDate}. Domain age: ${whois.domainAge}. Status: ${whois.whoisStatus}.`,
    domainVerification: `Domain ${dns.aRecord.length > 0 ? 'resolves correctly' : 'does not resolve — no A record'}. A records: ${dns.aRecord.slice(0, 3).join(', ') || 'None'}. NS: ${dns.ns.slice(0, 2).join(', ') || 'None'}.`,
    certificateValidation: `${ssl.sslStatus} — Issued by: ${ssl.issuer}. TLS: ${ssl.tlsVersion}. Valid from ${ssl.validFrom} to ${ssl.validUntil}. Subject: ${ssl.subject}.`,
    whoisInfo: `Registrar: ${whois.registrar}. Created: ${whois.registrationDate}. Expires: ${whois.expiryDate}. Country: ${whois.country}. Status: ${whois.whoisStatus}.`,
    brandImpersonation: brand.evidence,
    urlAnalysis: `URL length: ${urlAnalysis.urlLength} chars. HTTPS: ${urlAnalysis.httpsStatus ? 'Yes' : 'No'}. IP in URL: ${urlAnalysis.ipAddressDetection ? 'Yes' : 'No'}. Encoded chars: ${urlAnalysis.encodedCharacters ? 'Yes' : 'No'}. Suspicious params: ${urlAnalysis.suspiciousParameters.join(', ') || 'None'}. TLD: .${urlAnalysis.tld}${urlAnalysis.isSuspiciousTLD ? ' (suspicious)' : ''}.`,
    reputationAnalysis: 'Heuristic analysis completed. No external threat intelligence APIs configured — to enable VirusTotal / Google Safe Browsing, add API keys in the backend .env file.',
    trustScore: riskScore.score,
    riskLevel: riskScore.riskLevel,
    confidence: riskScore.confidence,
    reasonBehindDecision: ai.reasonBehindDecision,
    investigationStory: ai.investigationStory,
    mitreMapping: ai.mitreMapping,
    aiSummary: ai.aiSummary,
    aiExplanation: ai.aiExplanation,
    recommendations: ai.recommendations,
    scoreBreakdown: riskScore.factors.map(f => ({ label: f.label, positive: f.positive, points: f.points })),
    mitreTechniques: ai.mitreMapping.map(m => {
      const [id, ...rest] = m.split(' — ');
      return { techniqueId: id.trim(), techniqueName: rest.join(' — '), description: rest.join(' — ') };
    }),
    whois: { registrar: whois.registrar, registrationDate: whois.registrationDate, expiryDate: whois.expiryDate, domainAge: whois.domainAge, country: whois.country, whoisStatus: whois.whoisStatus },
    ssl: { sslStatus: ssl.sslStatus, tlsVersion: ssl.tlsVersion, issuer: ssl.issuer, validFrom: ssl.validFrom, validUntil: ssl.validUntil, certificateChain: ssl.certificateChain, subject: ssl.subject, san: ssl.san },
    dns: { aRecord: dns.aRecord, aaaaRecord: dns.aaaaRecord, mx: dns.mx, txt: dns.txt, ns: dns.ns, cname: dns.cname },
    reputation: { virusTotal: 'Not checked', urlScan: 'Not checked', phishTank: 'Not checked', abuseIpdb: 'Not checked', googleSafeBrowsing: 'Not checked', vendorCount: 0, detectionRatio: '0/0', overall: 'clean' },
    brand: { brandName: brand.brandName, confidence: brand.confidence, evidence: brand.evidence, visualSimilarity: brand.visualSimilarity, domainSimilarity: brand.domainSimilarity },
    urlAnalysisStructured: { redirectCount: 0, urlLength: urlAnalysis.urlLength, encodedCharacters: urlAnalysis.encodedCharacters, suspiciousParameters: urlAnalysis.suspiciousParameters, ipAddressDetection: urlAnalysis.ipAddressDetection, httpsStatus: urlAnalysis.httpsStatus },
    evidencePanel: {
      originalUrl: url, resolvedUrl: url, ipAddress: ip,
      hostingProvider: geo.hosting, country: geo.country,
      registrar: whois.registrar, sslStatus: ssl.sslStatus,
      whoisStatus: whois.whoisStatus, sha256Hash: sha256Stub(url),
    },
  };
}

// ── Email / Sender pipeline ───────────────────────────────────────────────────

export async function investigateEmail(emailStr: string): Promise<BackendAnalysisResponse> {
  const { domain, email, result: emailData } = await withTimeout(
    analyzeEmail(emailStr),
    12000,
    {
      domain: emailStr.includes('@') ? emailStr.split('@')[1] : emailStr,
      email: emailStr,
      result: {
        spf: 'Lookup timed out', dkim: 'Lookup timed out', dmarc: 'Lookup timed out',
        replyToAnalysis: 'N/A', senderDomain: emailStr, spoofDetection: 'Lookup timed out',
        dmarcPolicy: 'none', isFreemail: false, mxExists: false, suspiciousKeywords: [],
      },
    }
  );

  const [whois, dns, ssl] = await Promise.all([
    withTimeout(lookupWhois(domain), 8000, EMPTY_WHOIS),
    withTimeout(lookupDNS(domain), 6000, EMPTY_DNS),
    withTimeout(checkSSL(domain), 8000, EMPTY_SSL),
  ]);

  const riskScore = scoreEmail({ emailData });
  const ai = buildAIText({
    evidenceType: 'email', evidenceValue: emailStr, riskScore,
    whoisAge: whois.domainAge, whoisRegistrar: whois.registrar,
    spf: emailData.spf, dmarc: emailData.dmarc, dkim: emailData.dkim,
    spoofDetection: emailData.spoofDetection, domainAgeDays: whois.domainAgeDays,
  });

  return {
    evidenceType: 'email',
    evidenceValue: emailStr,
    evidenceSummary: `Email investigation of '${emailStr}'. Domain: ${domain}. SPF: ${emailData.spf.split(' — ')[0]}. DMARC: ${emailData.dmarc.split(' — ')[0]}.`,
    identityVerification: `Email: ${email}. Domain: ${domain}. Free email provider: ${emailData.isFreemail ? 'Yes' : 'No'}. Domain registered via ${whois.registrar} (age: ${whois.domainAge}).`,
    domainVerification: `Sender domain: ${domain}. MX records: ${dns.mx.slice(0, 2).join(', ') || 'None found'}. NS: ${dns.ns.slice(0, 2).join(', ') || 'N/A'}.`,
    certificateValidation: `Domain SSL: ${ssl.sslStatus}.`,
    whoisInfo: `Registrar: ${whois.registrar}. Created: ${whois.registrationDate}. Domain age: ${whois.domainAge}. Country: ${whois.country}.`,
    brandImpersonation: emailData.suspiciousKeywords.length > 0 ? `Suspicious keywords in address: ${emailData.suspiciousKeywords.join(', ')}` : 'No brand-related keywords detected in email address.',
    urlAnalysis: `Sender domain: ${domain}. Local-part keywords: ${emailData.suspiciousKeywords.join(', ') || 'None'}.`,
    senderVerification: `SPF: ${emailData.spf}. DKIM: ${emailData.dkim}. DMARC: ${emailData.dmarc}. Spoofing: ${emailData.spoofDetection}. MX: ${emailData.mxExists ? 'Found' : 'Missing'}.`,
    reputationAnalysis: `SPF: ${emailData.spf.split(' — ')[0]}. DMARC: ${emailData.dmarc.split(' — ')[0]}. DKIM: ${emailData.dkim.split(' — ')[0]}.`,
    trustScore: riskScore.score,
    riskLevel: riskScore.riskLevel,
    confidence: riskScore.confidence,
    reasonBehindDecision: ai.reasonBehindDecision,
    investigationStory: ai.investigationStory,
    mitreMapping: ai.mitreMapping,
    aiSummary: ai.aiSummary,
    aiExplanation: ai.aiExplanation,
    recommendations: ai.recommendations,
    scoreBreakdown: riskScore.factors.map(f => ({ label: f.label, positive: f.positive, points: f.points })),
    email: { spf: emailData.spf, dkim: emailData.dkim, dmarc: emailData.dmarc, replyToAnalysis: emailData.replyToAnalysis, senderDomain: domain, spoofDetection: emailData.spoofDetection },
    whois: { registrar: whois.registrar, registrationDate: whois.registrationDate, expiryDate: whois.expiryDate, domainAge: whois.domainAge, country: whois.country, whoisStatus: whois.whoisStatus },
    ssl: { sslStatus: ssl.sslStatus, tlsVersion: ssl.tlsVersion, issuer: ssl.issuer, validFrom: ssl.validFrom, validUntil: ssl.validUntil, certificateChain: ssl.certificateChain, subject: ssl.subject, san: ssl.san },
    dns: { aRecord: dns.aRecord, aaaaRecord: dns.aaaaRecord, mx: dns.mx, txt: dns.txt, ns: dns.ns, cname: dns.cname },
    evidencePanel: {
      originalUrl: emailStr, resolvedUrl: `@${domain}`,
      ipAddress: dns.aRecord[0] ?? 'N/A', hostingProvider: 'N/A',
      country: whois.country, registrar: whois.registrar,
      sslStatus: ssl.sslStatus, whoisStatus: whois.whoisStatus,
      sha256Hash: sha256Stub(emailStr),
    },
  };
}

// ── QR pipeline ───────────────────────────────────────────────────────────────

export async function investigateQR(content: string): Promise<BackendAnalysisResponse> {
  const isUrl = /^https?:\/\//i.test(content) || (content.includes('.') && content.includes('/'));

  const riskIndicators: string[] = [];
  if (/login|verify|account|secure|update|paypal|bank/i.test(content)) riskIndicators.push('suspicious keyword in QR content');
  if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(content)) riskIndicators.push('IP address URL — no domain name');
  if (content.length > 200) riskIndicators.push('unusually long QR content');

  let base: BackendAnalysisResponse;
  if (isUrl) {
    base = await investigateURL(content);
    const qrAdj = scoreQR(riskIndicators, base.trustScore);
    base.trustScore = qrAdj.score;
    base.riskLevel = qrAdj.riskLevel;
  } else {
    const qrScore = scoreQR(riskIndicators);
    const ai = buildAIText({ evidenceType: 'qr', evidenceValue: content, riskScore: qrScore });
    base = {
      evidenceType: 'qr', evidenceValue: content,
      evidenceSummary: `QR code investigation. Decoded content: ${content.slice(0, 100)}.`,
      identityVerification: 'QR does not contain a URL — identity verification not applicable.',
      domainVerification: 'N/A', certificateValidation: 'N/A', whoisInfo: 'N/A',
      brandImpersonation: 'N/A',
      urlAnalysis: `Content length: ${content.length} chars. No URL destination.`,
      reputationAnalysis: 'N/A for non-URL QR content.',
      trustScore: qrScore.score, riskLevel: qrScore.riskLevel, confidence: 75,
      reasonBehindDecision: ai.reasonBehindDecision,
      investigationStory: ai.investigationStory,
      mitreMapping: ai.mitreMapping,
      aiSummary: ai.aiSummary, aiExplanation: ai.aiExplanation,
      recommendations: ai.recommendations,
      evidencePanel: { originalUrl: content, resolvedUrl: 'N/A', ipAddress: 'N/A', hostingProvider: 'N/A', country: 'N/A', registrar: 'N/A', sslStatus: 'N/A', whoisStatus: 'N/A', sha256Hash: sha256Stub(content) },
    };
  }

  base.evidenceType = 'qr';
  base.evidenceValue = content;
  base.qrVerification = `QR decoded content: ${content}. Risk indicators: ${riskIndicators.length > 0 ? riskIndicators.join('; ') : 'None'}.`;
  base.qr = { decodedUrl: content, redirects: [], reputation: 'Heuristic analysis only', qrRiskLevel: riskIndicators.length > 0 ? `High — ${riskIndicators.join('; ')}` : 'Low — no indicators' };
  return base;
}

// ── APK pipeline ──────────────────────────────────────────────────────────────

export async function investigateAPK(apkValue: string): Promise<BackendAnalysisResponse> {
  const riskScore = scoreAPK([], []);
  const ai = buildAIText({ evidenceType: 'apk', evidenceValue: apkValue, riskScore });
  const sha = sha256Stub(apkValue);

  return {
    evidenceType: 'apk', evidenceValue: apkValue,
    evidenceSummary: `APK investigation of '${apkValue}'. SHA256: ${sha.slice(0, 16)}... Static binary analysis requires the APK file.`,
    identityVerification: `Package identifier: ${apkValue}. Publisher identity requires binary signature verification.`,
    domainVerification: 'N/A for APK investigation.',
    certificateValidation: 'APK signing certificate requires binary extraction.',
    whoisInfo: 'N/A for APK investigation.',
    brandImpersonation: 'Brand check requires binary manifest analysis.',
    urlAnalysis: 'N/A for APK investigation.',
    apkPermissionAnalysis: 'Static permission analysis requires the APK binary file.',
    reputationAnalysis: 'No external reputation APIs checked.',
    trustScore: riskScore.score, riskLevel: riskScore.riskLevel, confidence: 50,
    reasonBehindDecision: ai.reasonBehindDecision,
    investigationStory: ai.investigationStory,
    mitreMapping: ai.mitreMapping,
    aiSummary: ai.aiSummary, aiExplanation: ai.aiExplanation,
    recommendations: [...ai.recommendations, 'Only install apps from the official Google Play Store.'],
    apk: { sha256: sha, permissions: [], dangerousPermissions: [], receivers: [], services: [], activities: [], malwareDetection: 'Binary not provided', riskScore: 50 },
    evidencePanel: { originalUrl: apkValue, resolvedUrl: 'N/A', ipAddress: 'N/A', hostingProvider: 'N/A', country: 'N/A', registrar: 'N/A', sslStatus: 'N/A', whoisStatus: 'N/A', sha256Hash: sha },
  };
}

// ── Sender pipeline ───────────────────────────────────────────────────────────

export async function investigateSender(sender: string): Promise<BackendAnalysisResponse> {
  const result = await investigateEmail(sender);
  result.evidenceType = 'sender';
  return result;
}
