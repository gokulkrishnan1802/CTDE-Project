/** IP geolocation and hosting provider detection via free APIs. */

export interface GeoResult {
  ip: string;
  country: string;
  city: string;
  org: string;
  hosting: string;
}

const HOSTING_HINTS: [string, string][] = [
  ['cloudflare', 'Cloudflare'],
  ['amazon', 'Amazon AWS'],
  ['amazonaws', 'Amazon AWS'],
  ['google', 'Google Cloud'],
  ['microsoft', 'Microsoft Azure'],
  ['azure', 'Microsoft Azure'],
  ['digitalocean', 'DigitalOcean'],
  ['linode', 'Linode / Akamai'],
  ['akamai', 'Akamai'],
  ['fastly', 'Fastly'],
  ['github', 'GitHub Pages'],
  ['netlify', 'Netlify'],
  ['vercel', 'Vercel'],
  ['ovh', 'OVH'],
  ['hetzner', 'Hetzner'],
  ['vultr', 'Vultr'],
  ['hostinger', 'Hostinger'],
  ['godaddy', 'GoDaddy'],
  ['bluehost', 'Bluehost'],
];

function detectHosting(org: string): string {
  const lower = org.toLowerCase();
  for (const [hint, name] of HOSTING_HINTS) {
    if (lower.includes(hint)) return name;
  }
  return org || 'Unknown Hosting';
}

export async function geolocateIP(ip: string): Promise<GeoResult> {
  if (!ip || ip === 'N/A' || ip === 'Unresolvable') {
    return { ip, country: 'Unknown', city: 'Unknown', org: 'Unknown', hosting: 'Unknown' };
  }

  // ip-api.com — free, no key, supports HTTPS with JSON
  try {
    const res = await fetch(
      `https://ip-api.com/json/${encodeURIComponent(ip)}?fields=country,city,org,hosting`,
      { signal: AbortSignal.timeout(6000) },
    );
    if (res.ok) {
      const d = await res.json();
      const org = d.org ?? d.isp ?? 'Unknown';
      return {
        ip,
        country: d.country ?? 'Unknown',
        city: d.city ?? 'Unknown',
        org,
        hosting: detectHosting(org),
      };
    }
  } catch { /* fallback */ }

  // ipapi.co fallback
  try {
    const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      signal: AbortSignal.timeout(6000),
    });
    if (res.ok) {
      const d = await res.json();
      const org = d.org ?? d.as ?? 'Unknown';
      return {
        ip,
        country: d.country_name ?? 'Unknown',
        city: d.city ?? 'Unknown',
        org,
        hosting: detectHosting(org),
      };
    }
  } catch { /* ignore */ }

  return { ip, country: 'Unknown', city: 'Unknown', org: 'Unknown', hosting: 'Unknown Hosting' };
}

/** Resolve domain to IP using Cloudflare DoH */
export async function resolveIP(domain: string): Promise<string> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(6000) },
    );
    if (res.ok) {
      const data = await res.json();
      const answer = data?.Answer;
      if (Array.isArray(answer) && answer.length > 0) {
        // Type 1 = A record
        const a = answer.find((r: { type: number }) => r.type === 1);
        if (a) return a.data;
      }
    }
  } catch { /* ignore */ }
  return 'Unresolvable';
}
