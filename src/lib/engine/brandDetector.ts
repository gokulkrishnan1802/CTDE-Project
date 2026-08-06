/** Brand impersonation detection — heuristic, client-side only. */

export interface BrandResult {
  brandName: string;
  confidence: number;
  evidence: string;
  visualSimilarity: number;
  domainSimilarity: number;
  isOfficialDomain: boolean;
}

interface BrandEntry {
  name: string;
  keywords: string[];
  official: string[];
}

const BRANDS: BrandEntry[] = [
  { name: 'PayPal', keywords: ['paypal', 'paypai', 'paypa1', 'p4ypal'], official: ['paypal.com'] },
  { name: 'Amazon', keywords: ['amazon', 'amaz0n', 'arnazon', 'amazn'], official: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.ca'] },
  { name: 'Apple', keywords: ['apple', 'appleid', 'icloud', 'itunes'], official: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', keywords: ['microsoft', 'microsft', 'micros0ft', 'outlook', 'office365', 'onedrive'], official: ['microsoft.com', 'outlook.com', 'live.com', 'office.com'] },
  { name: 'Google', keywords: ['google', 'g00gle', 'g0ogle', 'gmail'], official: ['google.com', 'gmail.com', 'googlemail.com'] },
  { name: 'Facebook', keywords: ['facebook', 'faceb00k', 'facebok', 'fb'], official: ['facebook.com', 'fb.com'] },
  { name: 'Netflix', keywords: ['netflix', 'netf1ix', 'netfix'], official: ['netflix.com'] },
  { name: 'Instagram', keywords: ['instagram', 'instagrm', 'instagran'], official: ['instagram.com'] },
  { name: 'WhatsApp', keywords: ['whatsapp', 'whats-app', 'watsapp'], official: ['whatsapp.com'] },
  { name: 'HDFC Bank', keywords: ['hdfc', 'hdfcbank'], official: ['hdfcbank.com'] },
  { name: 'ICICI Bank', keywords: ['icici', 'icicbank'], official: ['icicibank.com'] },
  { name: 'SBI Bank', keywords: ['sbi', 'sbionline', 'onlinesbi'], official: ['onlinesbi.sbi', 'sbi.co.in'] },
  { name: 'Chase Bank', keywords: ['chase', 'chasebank'], official: ['chase.com'] },
  { name: 'Wells Fargo', keywords: ['wellsfargo', 'wells-fargo'], official: ['wellsfargo.com'] },
  { name: 'DHL', keywords: ['dhl'], official: ['dhl.com'] },
  { name: 'FedEx', keywords: ['fedex'], official: ['fedex.com'] },
  { name: 'UPS', keywords: ['ups'], official: ['ups.com'] },
  { name: 'Dropbox', keywords: ['dropbox', 'dr0pbox'], official: ['dropbox.com'] },
  { name: 'LinkedIn', keywords: ['linkedin', 'linkedln'], official: ['linkedin.com'] },
  { name: 'Twitter', keywords: ['twitter', 'twit'], official: ['twitter.com', 'x.com'] },
];

export function detectBrand(domain: string): BrandResult {
  const lower = domain.toLowerCase();
  // Strip common subdomains for matching
  const domainCore = lower.replace(/^(www|mail|secure|login|account|my|portal|online|app)\./i, '');

  for (const brand of BRANDS) {
    for (const kw of brand.keywords) {
      if (!domainCore.includes(kw)) continue;

      // Check if it IS the official domain
      const isOfficial = brand.official.some(off => domainCore === off || domainCore.endsWith(`.${off}`));
      if (isOfficial) {
        return {
          brandName: brand.name,
          confidence: 5,
          evidence: `Domain matches official ${brand.name} domain — legitimate.`,
          visualSimilarity: 1.0,
          domainSimilarity: 1.0,
          isOfficialDomain: true,
        };
      }

      // It contains the brand keyword but is NOT the official domain — impersonation risk
      const similarity = Math.min((kw.length / domainCore.split('.')[0].length) * 100, 100);
      const confidence = Math.min(60 + similarity * 0.4, 95);

      return {
        brandName: brand.name,
        confidence: Math.round(confidence),
        evidence: `Domain '${domain}' contains brand keyword '${kw}' but is NOT the official ${brand.name} domain (${brand.official[0]}). Possible impersonation.`,
        visualSimilarity: Math.round(similarity) / 100,
        domainSimilarity: Math.round(similarity) / 100,
        isOfficialDomain: false,
      };
    }
  }

  return {
    brandName: 'None',
    confidence: 0,
    evidence: 'No known brand impersonation detected in domain name.',
    visualSimilarity: 0,
    domainSimilarity: 0,
    isOfficialDomain: false,
  };
}
