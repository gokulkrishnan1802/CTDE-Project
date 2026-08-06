/** URL structure analysis — runs entirely client-side, no network calls. */

export interface URLAnalysisResult {
  redirectCount: number;
  urlLength: number;
  encodedCharacters: boolean;
  suspiciousParameters: string[];
  ipAddressDetection: boolean;
  httpsStatus: boolean;
  subdomain: string;
  domain: string;
  tld: string;
  path: string;
  isSuspiciousTLD: boolean;
  hasExcessiveSubdomains: boolean;
  homoglyphSuspicion: boolean;
  punycode: boolean;
  suspiciousKeywords: string[];
}

const SUSPICIOUS_TLD = new Set(['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'loan', 'work', 'racing', 'bid', 'date', 'faith', 'review', 'stream', 'download', 'party']);
const SUSPICIOUS_PARAMS = new Set(['redirect', 'url', 'next', 'goto', 'return', 'redir', 'target', 'dest', 'link', 'to', 'forward']);
const PHISH_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'update', 'account', 'confirm', 'validate', 'credential', 'password', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'support', 'helpdesk', 'admin', 'billing', 'invoice', 'suspended'];

export function analyzeURL(rawUrl: string): URLAnalysisResult {
  let url: URL;
  try {
    url = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
  } catch {
    return emptyURLResult(rawUrl);
  }

  const hostname = url.hostname.toLowerCase();
  const parts = hostname.split('.');
  const tld = parts[parts.length - 1] ?? '';
  const domain = parts.length >= 2 ? `${parts[parts.length - 2]}.${tld}` : hostname;
  const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '';

  const encodedChars = /%[0-9A-Fa-f]{2}/.test(rawUrl);
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isPunycode = hostname.includes('xn--');

  // Suspicious query parameters
  const suspiciousParams: string[] = [];
  url.searchParams.forEach((_, key) => {
    if (SUSPICIOUS_PARAMS.has(key.toLowerCase())) suspiciousParams.push(key);
  });

  // Suspicious keywords in URL (phishing indicators)
  const fullUrlLower = rawUrl.toLowerCase();
  const suspiciousKeywords = PHISH_KEYWORDS.filter(kw => fullUrlLower.includes(kw));

  // Homoglyph check (Cyrillic/lookalike characters in ASCII context)
  const homoglyph = /[аеорсухАВЕКМНОРСТУХ]/.test(rawUrl);

  return {
    redirectCount: 0, // filled in by pipeline after HTTP probe
    urlLength: rawUrl.length,
    encodedCharacters: encodedChars,
    suspiciousParameters: suspiciousParams,
    ipAddressDetection: isIP,
    httpsStatus: url.protocol === 'https:',
    subdomain,
    domain,
    tld,
    path: url.pathname,
    isSuspiciousTLD: SUSPICIOUS_TLD.has(tld),
    hasExcessiveSubdomains: parts.length > 4,
    homoglyphSuspicion: homoglyph,
    punycode: isPunycode,
    suspiciousKeywords,
  };
}

function emptyURLResult(raw: string): URLAnalysisResult {
  return {
    redirectCount: 0, urlLength: raw.length, encodedCharacters: false,
    suspiciousParameters: [], ipAddressDetection: false, httpsStatus: false,
    subdomain: '', domain: raw, tld: '', path: '',
    isSuspiciousTLD: false, hasExcessiveSubdomains: false,
    homoglyphSuspicion: false, punycode: false, suspiciousKeywords: [],
  };
}

export function extractDomain(value: string): string {
  try {
    if (value.includes('@')) return value.split('@')[1].toLowerCase().trim();
    const u = new URL(value.startsWith('http') ? value : `https://${value}`);
    return u.hostname.toLowerCase();
  } catch {
    return value.toLowerCase().replace(/^https?:\/\//i, '').split('/')[0];
  }
}

export function normalizeUrl(value: string): string {
  const v = value.trim();
  if (v.startsWith('http://') || v.startsWith('https://')) return v;
  return `https://${v}`;
}
