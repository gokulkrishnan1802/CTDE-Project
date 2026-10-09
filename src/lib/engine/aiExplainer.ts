/**
 * Rule-based AI explanation engine.
 * Uses collected evidence and describes the score as a heuristic assessment.
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

  const positive = factors.filter((factor) => factor.positive).map((factor) => factor.label);
  const negative = factors
    .filter((factor) => !factor.positive && factor.points < 0)
    .map((factor) => factor.label);

  const riskWord =
    riskLevel === 'Safe' ? 'low' : riskLevel === 'Suspicious' ? 'moderate' : 'high';

  let summary =
    `This ${evidenceType.toUpperCase()} investigation of '${evidenceValue}' resulted in a ` +
    `Trust Score of ${score}/100, indicating a ${riskWord} risk level (${riskLevel}).`;

  if (positive.length > 0) {
    summary += ` Positive signals: ${positive.slice(0, 2).join('; ')}.`;
  }
  if (negative.length > 0) {
    summary += ` Risk signals: ${negative.slice(0, 2).join('; ')}.`;
  }

  const explanationParts: string[] = [
    'This is a heuristic risk assessment based on the checks shown; it is not a probability or a measured accuracy result.',
  ];

  if (input.whoisAge && input.whoisAge !== 'Unknown') {
    explanationParts.push(
      `Domain age: ${input.whoisAge} — registered via ${input.whoisRegistrar ?? 'unknown registrar'}.`,
    );
  }
  if (input.sslStatus) {
    explanationParts.push(
      `SSL/TLS certificate status: ${input.sslStatus}` +
        `${input.tlsVersion ? ` using ${input.tlsVersion}` : ''}.`,
    );
  }
  if (input.brandName && input.brandName !== 'None' && input.brandEvidence) {
    explanationParts.push(`Brand analysis: ${input.brandEvidence}`);
  }
  if (input.spf) {
    explanationParts.push(`Email authentication — SPF: ${input.spf.split(' — ')[0] ?? input.spf}.`);
  }
  if (input.dmarc) {
    explanationParts.push(`DMARC: ${input.dmarc.split(' — ')[0] ?? input.dmarc}.`);
  }
  if (input.spoofDetection) {
    explanationParts.push(`Spoofing check: ${input.spoofDetection}.`);
  }
  if (input.ipAddress && input.ipAddress !== 'Unresolvable') {
    explanationParts.push(
      `Resolved IP: ${input.ipAddress}` +
        `${input.hosting ? ` hosted on ${input.hosting}` : ''}` +
        `${input.country ? ` in ${input.country}` : ''}.`,
    );
  }

  const storyParts = [
    `The CTDE pipeline processed the supplied ${evidenceType.toUpperCase()} evidence for '${evidenceValue}'.`,
  ];
  if (negative.length > 0) {
    storyParts.push(
      `The following risk factors contributed to the ${riskLevel} verdict: ${negative.slice(0, 3).join('; ')}.`,
    );
  } else {
    storyParts.push(
      'No negative score factors were recorded. This does not, by itself, establish that the evidence is trustworthy.',
    );
  }

  const mitre = buildMITREMapping(input, negative);
  const recommendations = buildRecommendations(input, riskLevel, negative);

  const reasonParts: string[] = [];
  if (negative.length > 0) {
    reasonParts.push(`Risk factors: ${negative.slice(0, 3).join('; ')}`);
  }
  if (positive.length > 0) {
    reasonParts.push(`Trust factors: ${positive.slice(0, 2).join('; ')}`);
  }
  const reasonBehindDecision =
    `${reasonParts.join(' | ')}. Final score: ${score}/100.`;

  return {
    aiSummary: summary,
    aiExplanation: explanationParts.join(' '),
    investigationStory: storyParts.join(' '),
    mitreMapping: mitre,
    recommendations,
    reasonBehindDecision,
  };
}

function buildMITREMapping(input: ExplainInput, negativeFactors: string[]): string[] {
  const techniques: string[] = [];

  if (
    input.brandName &&
    input.brandName !== 'None' &&
    !(input.brandEvidence ?? '').includes('legitimate')
  ) {
    techniques.push(
      'T1566.002 — Phishing: Spearphishing Link (brand impersonation via lookalike domain)',
    );
  }
  if (negativeFactors.some((factor) => factor.includes('IP address'))) {
    techniques.push(
      'T1071.001 — Application Layer Protocol: IP-based URL to bypass domain filtering',
    );
  }
  if (
    negativeFactors.some(
      (factor) => factor.includes('newly registered') || factor.includes('brand-new'),
    )
  ) {
    techniques.push(
      'T1583.001 — Acquire Infrastructure: Newly registered domain used for attack',
    );
  }
  if (
    negativeFactors.some(
      (factor) => factor.includes('subdomain') || factor.includes('Punycode'),
    )
  ) {
    techniques.push(
      'T1036.005 — Masquerading: Match Legitimate Name or Location via subdomain/homograph',
    );
  }
  if (
    negativeFactors.some(
      (factor) =>
        factor.includes('SPF') ||
        factor.includes('DMARC') ||
        factor.includes('spoofing'),
    )
  ) {
    techniques.push(
      'T1534 — Internal Spearphishing / Email Spoofing (missing email authentication)',
    );
  }
  if (
    negativeFactors.some(
      (factor) => factor.includes('encoded') || factor.includes('keyword'),
    )
  ) {
    techniques.push('T1027 — Obfuscated Files or Information: URL obfuscation');
  }
  if (input.evidenceType === 'qr') {
    techniques.push('T1566.002 — Phishing via QR Code (Quishing)');
  }
  if (input.evidenceType === 'apk') {
    techniques.push('T1476 — Deliver Malicious App via Other Means (sideloaded APK)');
    techniques.push(
      'T1421 — System Network Connections Discovery via dangerous permissions',
    );
  }

  if (techniques.length === 0) {
    techniques.push(
      'T1598.003 — Phishing for Information: no confirmed active techniques — continue monitoring',
    );
  }
  return techniques;
}

function buildRecommendations(
  input: ExplainInput,
  riskLevel: string,
  negativeFactors: string[],
): string[] {
  const recommendations: string[] = [];

  if (riskLevel === 'Dangerous') {
    recommendations.push(
      `Do NOT visit or interact with this ${input.evidenceType.toUpperCase()} — multiple high-risk indicators were detected.`,
    );
    recommendations.push(
      'Report this URL to Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/',
    );
  }

  if (negativeFactors.some((factor) => factor.includes('brand impersonation'))) {
    recommendations.push(
      `This resource impersonates '${input.brandName}'. Navigate to the official website directly via a trusted bookmark.`,
    );
  }
  if (
    negativeFactors.some(
      (factor) =>
        factor.includes('newly registered') ||
        factor.includes('brand-new') ||
        factor.includes('< 3 months'),
    )
  ) {
    recommendations.push(
      'Treat this domain with caution — newly registered domains are a primary indicator of phishing infrastructure.',
    );
  }
  if (
    negativeFactors.some(
      (factor) => factor.includes('SSL') || factor.includes('HTTPS'),
    )
  ) {
    recommendations.push(
      'This site lacks a valid SSL certificate — any data entered would be transmitted unencrypted.',
    );
  }
  if (
    negativeFactors.some(
      (factor) => factor.includes('SPF') || factor.includes('DMARC'),
    )
  ) {
    recommendations.push(
      'The sender domain lacks proper email authentication (SPF/DMARC) — this email could be spoofed.',
    );
    recommendations.push(
      'Verify the sender through an independent channel (phone call, official website) before taking action.',
    );
  }
  if (negativeFactors.some((factor) => factor.includes('spoofing'))) {
    recommendations.push(
      'Do NOT click links or download attachments without confirming the sender identity through a separate channel.',
    );
  }
  if (negativeFactors.some((factor) => factor.includes('IP address'))) {
    recommendations.push(
      'Legitimate websites use domain names, not raw IP addresses. Avoid entering credentials on this site.',
    );
  }
  if (input.evidenceType === 'qr') {
    recommendations.push('Always preview the destination URL before following a QR code link.');
    recommendations.push(
      'Verify QR codes from physical locations have not been tampered with (sticker over original).',
    );
  }
  if (input.evidenceType === 'apk') {
    recommendations.push(
      'Only install Android apps from the official Google Play Store or verified sources.',
    );
    recommendations.push('Review all permissions requested by the app before installation.');
  }

  if (riskLevel === 'Safe' && recommendations.length === 0) {
    recommendations.push(
      'No immediate action required — continue exercising standard security hygiene.',
    );
    recommendations.push('Verify the URL matches what you expect before entering credentials.');
    recommendations.push('Keep your browser and security software up to date.');
  }

  return recommendations.length > 0
    ? recommendations
    : ['Continue monitoring. No specific actions required at this time.'];
}

/** Answer a question about an investigation using only its evidence data. */
export function answerQuestion(
  question: string,
  investigation: Record<string, unknown>,
): string {
  const q = question.toLowerCase();
  const risk = String(investigation['riskLevel'] ?? 'Unknown');
  const score = Number(investigation['trustScore'] ?? 0);
  const evidenceType = String(investigation['evidenceType'] ?? 'evidence');
  const evidenceValue = String(investigation['evidenceValue'] ?? '');

  if (/why.*(safe|dangerous|suspicious|risk|score|decision|result)/i.test(q)) {
    return (
      `The ${evidenceType} '${evidenceValue}' received a Trust Score of ${score}/100 (${risk}). ` +
      `${String(investigation['reasonBehindDecision'] ?? '')} ` +
      'This score is a heuristic assessment, not a statistically validated probability or confirmed malware verdict.'
    );
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
    const recommendations = investigation['recommendations'];
    if (Array.isArray(recommendations) && recommendations.length > 0) {
      return `Based on the investigation findings:\n${recommendations
        .map((item, index) => `${index + 1}. ${item}`)
        .join('\n')}`;
    }
    return 'No specific recommendations available for this investigation.';
  }
  if (/mitre|att&?ck|technique/i.test(q)) {
    const mitre = investigation['mitreMapping'];
    if (Array.isArray(mitre) && mitre.length > 0) {
      return `MITRE ATT&CK techniques identified:\n${mitre.join('\n')}`;
    }
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

  return (
    `The ${evidenceType} '${evidenceValue}' has a Trust Score of ${score}/100 (${risk}). ` +
    `Ask a more specific question such as: "Why is this ${risk}?", ` +
    '"Explain the SSL findings", "What are the recommendations?", or "Show MITRE mapping."'
  );
}