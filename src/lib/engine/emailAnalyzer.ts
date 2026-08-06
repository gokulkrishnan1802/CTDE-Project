/** Email / sender investigation — SPF, DMARC, DKIM, spoofing analysis. */

import { getSPFRecord, getDMARCRecord, getDMARCPolicy, findDKIMSelector, lookupDNS } from './dnsLookup';

export interface EmailAnalysisResult {
  spf: string;
  dkim: string;
  dmarc: string;
  replyToAnalysis: string;
  senderDomain: string;
  spoofDetection: string;
  dmarcPolicy: string;
  isFreemail: boolean;
  mxExists: boolean;
  suspiciousKeywords: string[];
}

const FREEMAIL = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
  'icloud.com', 'protonmail.com', 'aol.com', 'mail.com', 'zoho.com',
  'yandex.com', 'yahoo.co.in', 'rediffmail.com',
]);

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'update', 'confirm', 'paypal',
  'amazon', 'apple', 'microsoft', 'support', 'helpdesk', 'admin',
  'noreply', 'billing', 'invoice', 'alert', 'notification', 'bank',
];

export async function analyzeEmail(emailOrDomain: string): Promise<{ domain: string; email: string; result: EmailAnalysisResult }> {
  let domain: string;
  let email: string;

  if (emailOrDomain.includes('@')) {
    email = emailOrDomain.trim().toLowerCase();
    domain = email.split('@')[1];
  } else {
    domain = emailOrDomain.trim().toLowerCase();
    email = `unknown@${domain}`;
  }

  const localPart = email.split('@')[0];

  const [spfRecord, dmarcRecord, dmarcPolicy, dkimSelector, dns] = await Promise.all([
    getSPFRecord(domain),
    getDMARCRecord(domain),
    getDMARCPolicy(domain),
    findDKIMSelector(domain),
    lookupDNS(domain),
  ]);

  // SPF
  let spf: string;
  if (spfRecord) {
    if (spfRecord.includes('~all') || spfRecord.includes('?all')) {
      spf = `Weak — SPF exists but uses soft-fail (~all): ${spfRecord.slice(0, 80)}`;
    } else if (spfRecord.includes('-all')) {
      spf = `Pass — strict SPF policy (-all): ${spfRecord.slice(0, 80)}`;
    } else {
      spf = `Pass — SPF record found: ${spfRecord.slice(0, 80)}`;
    }
  } else {
    spf = 'Fail — no SPF record found for this domain';
  }

  // DKIM
  let dkim: string;
  if (dkimSelector) {
    dkim = `Pass — DKIM key found (selector: ${dkimSelector})`;
  } else {
    dkim = 'Unknown — no common DKIM selectors found (full verification requires raw email headers)';
  }

  // DMARC
  let dmarc: string;
  if (dmarcRecord) {
    if (dmarcPolicy === 'reject') {
      dmarc = `Pass — DMARC policy: reject (strict) — ${dmarcRecord.slice(0, 80)}`;
    } else if (dmarcPolicy === 'quarantine') {
      dmarc = `Pass — DMARC policy: quarantine — ${dmarcRecord.slice(0, 80)}`;
    } else {
      dmarc = `Weak — DMARC policy: none (monitoring only) — ${dmarcRecord.slice(0, 80)}`;
    }
  } else {
    dmarc = 'Fail — no DMARC record found for this domain';
  }

  // Spoofing detection
  const spoofIndicators: string[] = [];
  if (!spfRecord) spoofIndicators.push('missing SPF');
  if (!dmarcRecord || dmarcPolicy === 'none') spoofIndicators.push(dmarcRecord ? 'weak DMARC (p=none)' : 'missing DMARC');
  if (SUSPICIOUS_KEYWORDS.some(kw => localPart.includes(kw))) spoofIndicators.push('sensitive keyword in local part');
  if (SUSPICIOUS_KEYWORDS.some(kw => domain.includes(kw) && !FREEMAIL.has(domain))) spoofIndicators.push('suspicious keyword in domain');

  const spoofDetection = spoofIndicators.length > 0
    ? `Potential spoofing risk — ${spoofIndicators.join(', ')}`
    : 'No spoofing indicators detected';

  // Suspicious keywords
  const combined = `${localPart} ${domain}`.toLowerCase();
  const suspiciousKeywords = SUSPICIOUS_KEYWORDS.filter(kw => combined.includes(kw));

  const isFreemail = FREEMAIL.has(domain);
  const mxExists = dns.mx.length > 0;

  return {
    domain,
    email,
    result: {
      spf,
      dkim,
      dmarc,
      replyToAnalysis: `Sender domain: ${domain} — reply-to analysis requires raw email headers`,
      senderDomain: domain,
      spoofDetection,
      dmarcPolicy,
      isFreemail,
      mxExists,
      suspiciousKeywords,
    },
  };
}
