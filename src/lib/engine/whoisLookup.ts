/** WHOIS data via RDAP — free, no API key, CORS-enabled. */

export interface WhoisResult {
  registrar: string;
  registrationDate: string;
  expiryDate: string;
  domainAge: string;
  domainAgeDays: number | null;
  country: string;
  whoisStatus: string;
  nameservers: string[];
}

export async function lookupWhois(domain: string): Promise<WhoisResult> {
  // Try rdap.org (aggregates multiple RDAP servers)
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const data = await res.json();
      return parseRDAP(data);
    }
  } catch { /* fallback */ }

  // Fallback: who-dat
  try {
    const res = await fetch(`https://who-dat.as93.net/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) {
      const data = await res.json();
      return parseWhoDat(data);
    }
  } catch { /* fallback */ }

  return emptyWhois();
}

function parseRDAP(data: Record<string, unknown>): WhoisResult {
  const events = (data.events as { eventAction: string; eventDate: string }[]) ?? [];
  const getEvent = (action: string) =>
    events.find(e => e.eventAction === action)?.eventDate ?? null;

  const registrationRaw = getEvent('registration');
  const expiryRaw = getEvent('expiration');

  const registrationDate = registrationRaw ? fmtDate(registrationRaw) : 'Unknown';
  const expiryDate = expiryRaw ? fmtDate(expiryRaw) : 'Unknown';
  const domainAgeDays = registrationRaw ? calcAgeDays(registrationRaw) : null;
  const domainAge = domainAgeDays !== null ? formatAge(domainAgeDays) : 'Unknown';

  const entities = (data.entities as Record<string, unknown>[]) ?? [];
  let registrar = 'Unknown';
  for (const entity of entities) {
    const roles = (entity.roles as string[]) ?? [];
    if (roles.includes('registrar')) {
      const vcardArray = (entity.vcardArray as unknown[][]) ?? [];
      const fn = vcardArray[1]?.find?.((v: unknown) => Array.isArray(v) && v[0] === 'fn');
      if (fn && Array.isArray(fn)) registrar = String(fn[3] ?? 'Unknown');
      break;
    }
  }

  const ns: string[] = ((data.nameservers as { ldhName: string }[]) ?? []).map(n => n.ldhName ?? '');
  const statusArr = (data.status as string[]) ?? [];

  return {
    registrar,
    registrationDate,
    expiryDate,
    domainAge,
    domainAgeDays,
    country: 'Unknown',
    whoisStatus: statusArr.slice(0, 3).join(', ') || 'Unknown',
    nameservers: ns.filter(Boolean),
  };
}

function parseWhoDat(data: Record<string, unknown>): WhoisResult {
  const reg = (data.created_date as string) ?? null;
  const exp = (data.expiration_date as string) ?? null;
  const ageDays = reg ? calcAgeDays(reg) : null;
  return {
    registrar: (data.registrar as string) ?? 'Unknown',
    registrationDate: reg ? fmtDate(reg) : 'Unknown',
    expiryDate: exp ? fmtDate(exp) : 'Unknown',
    domainAge: ageDays !== null ? formatAge(ageDays) : 'Unknown',
    domainAgeDays: ageDays,
    country: (data.registrant_country as string) ?? 'Unknown',
    whoisStatus: (data.status as string) ?? 'Unknown',
    nameservers: (data.name_servers as string[]) ?? [],
  };
}

function emptyWhois(): WhoisResult {
  return {
    registrar: 'Lookup failed',
    registrationDate: 'Unknown',
    expiryDate: 'Unknown',
    domainAge: 'Unknown',
    domainAgeDays: null,
    country: 'Unknown',
    whoisStatus: 'Unknown',
    nameservers: [],
  };
}

function fmtDate(raw: string): string {
  try {
    return new Date(raw).toISOString().slice(0, 10);
  } catch {
    return raw.slice(0, 10);
  }
}

function calcAgeDays(raw: string): number {
  try {
    const created = new Date(raw).getTime();
    const now = Date.now();
    return Math.floor((now - created) / 86_400_000);
  } catch {
    return 0;
  }
}

function formatAge(days: number): string {
  const years = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  if (years > 0) return months > 0 ? `${years} year${years > 1 ? 's' : ''} ${months} month${months > 1 ? 's' : ''}` : `${years} year${years > 1 ? 's' : ''}`;
  if (months > 0) return `${months} month${months > 1 ? 's' : ''}`;
  return `${days} day${days !== 1 ? 's' : ''}`;
}
