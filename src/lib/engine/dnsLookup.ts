/** DNS lookups via Cloudflare DNS-over-HTTPS — CORS enabled, no API key needed. */

const DOH_URL = 'https://cloudflare-dns.com/dns-query';

interface DoHResponse {
  Status: number;
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

async function query(name: string, type: string): Promise<string[]> {
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data: DoHResponse = await res.json();
    if (data.Status !== 0 || !data.Answer) return [];
    return data.Answer.map(r => r.data.replace(/"/g, '').trim()).filter(Boolean);
  } catch {
    return [];
  }
}

export interface DNSResult {
  aRecord: string[];
  aaaaRecord: string[];
  mx: string[];
  txt: string[];
  ns: string[];
  cname: string[];
}

export async function lookupDNS(domain: string): Promise<DNSResult> {
  const [a, aaaa, mx, txt, ns, cname] = await Promise.all([
    query(domain, 'A'),
    query(domain, 'AAAA'),
    query(domain, 'MX'),
    query(domain, 'TXT'),
    query(domain, 'NS'),
    query(domain, 'CNAME'),
  ]);
  return { aRecord: a, aaaaRecord: aaaa, mx, txt, ns, cname };
}

export async function hasSPF(domain: string): Promise<boolean> {
  const txt = await query(domain, 'TXT');
  return txt.some(r => r.includes('v=spf1'));
}

export async function getSPFRecord(domain: string): Promise<string | null> {
  const txt = await query(domain, 'TXT');
  return txt.find(r => r.includes('v=spf1')) ?? null;
}

export async function hasDMARC(domain: string): Promise<boolean> {
  const txt = await query(`_dmarc.${domain}`, 'TXT');
  return txt.some(r => r.includes('v=DMARC1'));
}

export async function getDMARCRecord(domain: string): Promise<string | null> {
  const txt = await query(`_dmarc.${domain}`, 'TXT');
  return txt.find(r => r.includes('v=DMARC1')) ?? null;
}

export async function getDMARCPolicy(domain: string): Promise<string> {
  const rec = await getDMARCRecord(domain);
  if (!rec) return 'none';
  const match = rec.match(/p=([^;]+)/);
  return match ? match[1].trim() : 'none';
}

export async function checkDKIMSelector(domain: string, selector: string): Promise<boolean> {
  const txt = await query(`${selector}._domainkey.${domain}`, 'TXT');
  return txt.length > 0;
}

/** Try common DKIM selectors — all in parallel so we never wait 9×timeout */
export async function findDKIMSelector(domain: string): Promise<string | null> {
  const selectors = ['default', 'google', 'mail', 'k1', 's1', 's2', 'selector1', 'selector2', 'dkim'];
  const results = await Promise.all(
    selectors.map(async sel => ({ sel, found: await checkDKIMSelector(domain, sel) }))
  );
  return results.find(r => r.found)?.sel ?? null;
}
