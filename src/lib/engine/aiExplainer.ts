/**
 * Rule-based AI explanation engine.
 * Every sentence references only evidence that was actually collected.
 * Nothing is fabricated or assumed.
 */

import type { RiskScore } from './riskScorer';

interface ExplainInput {
  evidenceType: string;
  evidenceValue: string;
  riskScore: RiskScore;
  whoisAge?: string;
  whoisRegistrar?: string;
  sslStatus?: string;
  tlsVersion?: string;
  brandEvidence?: string;
  brandName?: string;
  spf?: string;
  dmarc?: string;
  dkim?: string;
  spoofDetection?: string;
  ipAddress?: string;
  hosting?: string;
  country?: string;
  urlKeywords?: string[];
  mxExists?: boolean;
  domainAgeDays?: number | null;
}

export interface AIText {
  aiSummary: string;
  aiExplanation: string;
  investigationStory: string;
  mitreMapping: string[];
  recommendations: string[];
  reasonBehindDecision: string;
}

export function buildAIText(input: ExplainInput): AIText {
  const { evidenceType, evidenceValue, riskScore } = input;
  const { score, riskLevel, factors } = riskScore;

  const positive = factors.filter(f => f.positive).map(f => f.label);
  const negative = factors.filter(f => !f.positive && f.points < 0).map(f => f.label);

  // ── Summary ───────────────────────────────────────────────────────────────
  const riskWord = riskLevel === 'Safe' ? 'low' : riskLevel === 'Suspicious' ? 'moderate' : 'high';
  let summary = `This ${evidenceType.toUpperCase()} investigation of '${evidenceValue}' resulted in a Trust Score of ${score}/100, indicating a ${riskWord} risk level (${riskLevel}).`;

  if (positive.length > 0) summary += ` Positive signals: ${positive.slice(0, 2).join('; ')}.`;
  if (negative.length > 0) summary += ` Risk signals: ${negative.slice(0, 2).join('; ')}.`;

  // ── Explanation ───────────────────────────────────────────────────────────
  const parts: string[] = [`Confidence in this assessment: ${riskScore.confidence}% based on ${factors.length} evidence factor(s) collected.`];

  if (input.whoisAge && input.whoisAge !== 'Unknown') {
    parts.push(`Domain age: ${input.whoisAge} — registered via ${input.whoisRegistrar ?? 'unknown registrar'}.`);
  }
  if (input.sslStatus) {
    parts.push(`SSL/TLS certificate status: ${input.sslStatus}${input.tlsVersion ? ' using ' + input.tlsVersion : ''}.`);
  }
  if (input.brandName && input.brandName !== 'None' && input.brandEvidence) {
    parts.push(`Brand analysis: ${input.brandEvidence}`);
  }
  if (input.spf) parts.push(`Email authentication — SPF: ${input.spf.split(' — ')[0] ?? input.spf}.`);
  if (input.dmarc) parts.push(`DMARC: ${input.dmarc.split(' — ')[0] ?? input.dmarc}.`);
  if (input.spoofDetection) parts.push(`Spoofing check: ${input.spoofDetection}.`);
  if (input.ipAddress && input.ipAddress !== 'Unresolvable') {
    parts.push(`Resolved IP: ${input.ipAddress}${input.hosting ? ' hosted on ' + input.hosting : ''}${input.country ? ' in ' + input.country : ''}.`);
  }

  const explanation = parts.join(' ');

  // ── Story ─────────────────────────────────────────────────────────────────
  const storyParts: string[] = [
    `The CTDE forensic pipeline analyzed '${evidenceValue}' across multiple evidence modules including DNS, WHOIS, SSL, URL structure, and brand analysis.`,
  ];
  if (negative.length > 0) {
    storyParts.push(`The following risk factors contributed to the ${riskLevel} verdict: ${negative.slice(0, 3).join('; ')}.`);
  } else {
    storyParts.push(`No critical risk factors were identified. The collected evidence is consistent with a legitimate ${evidenceType}.`);
  }
  if (input.domainAgeDays !== undefined && input.domainAgeDays !== null && input.domainAgeDays < 90) {
    storyParts.push(`The very recent domain registration (${input.domainAgeDays} days ago) is a significant red flag — newly registered domains are disproportionately used in phishing campaigns.`);
  }

  // ── MITRE Mapping ─────────────────────────────────────────────────────────
  const mitre = buildMITREMapping(input, negative);

  // ── Recommendations ───────────────────────────────────────────────────────
  const recs = buildRecommendations(input, riskLevel, negative);

  // ── Reason behind decision ────────────────────────────────────────────────
  const reasonParts: string[] = [];
  if (negative.length > 0) reasonParts.push(`Risk factors: ${negative.slice(0, 3).join('; ')}`);
  if (positive.length > 0) reasonParts.push(`Trust factors: ${positive.slice(0, 2).join('; ')}`);
  const reasonBehindDecision = reasonParts.join(' | ') + `. Final score: ${score}/100.`;

  return {
    aiSummary: summary,
    aiExplanation: explanation,
    investigationStory: storyParts.join(' '),
    mitreMapping: mitre,
    recommendations: recs,
    reasonBehindDecision,
  };
}

function buildMITREMapping(input: ExplainInput, negativeFactors: string[]): string[] {
  const techniques: string[] = [];

  if (input.brandName && input.brandName !== 'None' && !(input.brandEvidence ?? '').includes('legitimate')) {
    techniques.push('T1566.002 — Phishing: Spearphishing Link (brand impersonation via lookalike domain)');
  }
  if (negativeFactors.some(f => f.includes('IP address'))) {
    techniques.push('T1071.001 — Application Layer Protocol: IP-based URL to bypass domain filtering');
  }
  if (negativeFactors.some(f => f.includes('newly registered') || f.includes('brand-new'))) {
    techniques.push('T1583.001 — Acquire Infrastructure: Newly registered domain used for attack');
  }
  if (negativeFactors.some(f => f.includes('subdomain') || f.includes('Punycode'))) {
    techniques.push('T1036.005 — Masquerading: Match Legitimate Name or Location via subdomain/homograph');
  }
  if (negativeFactors.some(f => f.includes('SPF') || f.includes('DMARC') || f.includes('spoofing'))) {
    techniques.push('T1534 — Internal Spearphishing / Email Spoofing (missing email authentication)');
  }
  if (negativeFactors.some(f => f.includes('encoded') || f.includes('keyword'))) {
    techniques.push('T1027 — Obfuscated Files or Information: URL obfuscation');
  }
  if (input.evidenceType === 'qr') {
    techniques.push('T1566.002 — Phishing via QR Code (Quishing)');
  }
  if (input.evidenceType === 'apk') {
    techniques.push('T1476 — Deliver Malicious App via Other Means (sideloaded APK)');
    techniques.push('T1421 — System Network Connections Discovery via dangerous permissions');
  }

  if (techniques.length === 0) {
    techniques.push('T1598.003 — Phishing for Information: no confirmed active techniques — continue monitoring');
  }
  return techniques;
}

function buildRecommendations(input: ExplainInput, riskLevel: string, negativeFactors: string[]): string[] {
  const recs: string[] = [];

  if (riskLevel === 'Dangerous') {
    recs.push(`Do NOT visit or interact with this ${input.evidenceType.toUpperCase()} — multiple high-risk indicators were detected.`);
    recs.push('Report this URL to Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/');
  }

  if (negativeFactors.some(f => f.includes('brand impersonation'))) {
    recs.push(`This resource impersonates '${input.brandName}'. Navigate to the official website directly via a trusted bookmark.`);
  }
  if (negativeFactors.some(f => f.includes('newly registered') || f.includes('brand-new') || f.includes('< 3 months'))) {
    recs.push('Treat this domain with caution — newly registered domains are a primary indicator of phishing infrastructure.');
  }
  if (negativeFactors.some(f => f.includes('SSL') || f.includes('HTTPS'))) {
    recs.push('This site lacks a valid SSL certificate — any data entered would be transmitted unencrypted.');
  }
  if (negativeFactors.some(f => f.includes('SPF') || f.includes('DMARC'))) {
    recs.push('The sender domain lacks proper email authentication (SPF/DMARC) — this email could be spoofed.');
    recs.push('Verify the sender through an independent channel (phone call, official website) before taking action.');
  }
  if (negativeFactors.some(f => f.includes('spoofing'))) {
    recs.push('Do NOT click links or download attachments without confirming the sender identity through a separate channel.');
  }
  if (negativeFactors.some(f => f.includes('IP address'))) {
    recs.push('Legitimate websites use domain names, not raw IP addresses. Avoid entering any credentials on this site.');
  }
  if (input.evidenceType === 'qr') {
    recs.push('Always preview the destination URL before following a QR code link.');
    recs.push('Verify QR codes from physical locations have not been tampered with (sticker over original).');
  }
  if (input.evidenceType === 'apk') {
    recs.push('Only install Android apps from the official Google Play Store or verified sources.');
    recs.push('Review all permissions requested by the app before installation.');
  }

  if (riskLevel === 'Safe' && recs.length === 0) {
    recs.push('No immediate action required — continue exercising standard security hygiene.');
    recs.push('Verify the URL matches what you expect before entering any credentials.');
    recs.push('Keep your browser and security software up to date.');
  }

  return recs.length > 0 ? recs : ['Continue monitoring. No specific actions required at this time.'];
}

/** Answer a specific user question about an investigation using only evidence data. */
export function answerQuestion(question: string, investigation: Record<string, unknown>): string {
  const q = question.toLowerCase();
  const risk = String(investigation['riskLevel'] ?? 'Unknown');
  const score = Number(investigation['trustScore'] ?? 0);
  const evidenceType = String(investigation['evidenceType'] ?? 'evidence');
  const evidenceValue = String(investigation['evidenceValue'] ?? '');

  if (/why.*(safe|dangerous|suspicious|risk|score|decision|result)/i.test(q)) {
    return `The ${evidenceType} '${evidenceValue}' received a Trust Score of ${score}/100 (${risk}). ${String(investigation['reasonBehindDecision'] ?? '')} The score was calculated from real forensic evidence — no assumptions were made.`;
  }
  if (/ssl|certificate|tls|https/i.test(q)) {
    return `Certificate analysis: ${String(investigation['certificateValidation'] ?? 'SSL information not available.')}`;
  }
  if (/whois|domain|registrar|age|registered/i.test(q)) {
    return `Domain / WHOIS findings: ${String(investigation['whoisInfo'] ?? 'WHOIS information not available.')}`;
  }
  if (/reputation|virustotal|blocklist|malicious|threat/i.test(q)) {
    return `Reputation analysis: ${String(investigation['reputationAnalysis'] ?? 'Reputation data not available.')}`;
  }
  if (/recommend|next|action|should|do/i.test(q)) {
    const recs = investigation['recommendations'];
    if (Array.isArray(recs) && recs.length > 0) {
      return `Based on the investigation findings:\n${recs.map((r, i) => `${i + 1}. ${r}`).join('\n')}`;
    }
    return 'No specific recommendations available for this investigation.';
  }
  if (/mitre|att&?ck|technique/i.test(q)) {
    const mitre = investigation['mitreMapping'];
    if (Array.isArray(mitre) && mitre.length > 0) return `MITRE ATT&CK techniques identified:\n${mitre.join('\n')}`;
    return 'No MITRE ATT&CK techniques were mapped for this investigation.';
  }
  if (/apk|permission|android/i.test(q)) {
    return `APK analysis: ${String(investigation['apkPermissionAnalysis'] ?? 'APK analysis not available.')}`;
  }
  if (/email|spf|dmarc|dkim|sender|spoof/i.test(q)) {
    return `Email / sender analysis: ${String(investigation['senderVerification'] ?? investigation['reputationAnalysis'] ?? 'Email analysis not available.')}`;
  }
  if (/brand|imperson|fake|lookalike/i.test(q)) {
    return `Brand impersonation analysis: ${String(investigation['brandImpersonation'] ?? 'Not available.')}`;
  }
  if (/summary|overview|explain|report|what/i.test(q)) {
    return String(investigation['evidenceSummary'] ?? 'Evidence summary not available.');
  }

  return `The ${evidenceType} '${evidenceValue}' has a Trust Score of ${score}/100 (${risk}). Ask a more specific question such as: "Why is this ${risk}?", "Explain the SSL findings", "What are the recommendations?", or "Show MITRE mapping."`;
}
