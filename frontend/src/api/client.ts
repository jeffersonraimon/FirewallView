import { FirewallRule, AddressList, SimulationPacket, SimulationResult } from '../types';

const API_BASE = '/api';

// FastAPI returns `detail` as a string (HTTPException) or as an array of
// validation errors (422). Format both readably.
function formatDetail(detail: unknown): string | null {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((item: any) => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object') {
        const loc = Array.isArray(item.loc)
          ? item.loc.filter((l: unknown) => l !== 'body').join('.')
          : '';
        const msg = item.msg ?? JSON.stringify(item);
        return loc ? `${loc}: ${msg}` : String(msg);
      }
      return String(item);
    });
    return parts.join('; ');
  }
  if (detail && typeof detail === 'object') return JSON.stringify(detail);
  return null;
}

async function errorFromResponse(res: Response, prefix: string): Promise<Error> {
  const data = await res.json().catch(() => ({}));
  const detail = formatDetail((data as any)?.detail);
  return new Error(detail ? `${prefix}: ${detail}` : `${prefix}: ${res.status} ${res.statusText}`.trim());
}

export async function fetchPreset(name: string): Promise<{ rules: FirewallRule[]; address_lists: Record<string, AddressList> }> {
  const res = await fetch(`${API_BASE}/presets/${name}`);
  if (!res.ok) throw await errorFromResponse(res, 'Falha ao carregar preset');
  return res.json();
}

export async function runSimulation(
  packet: SimulationPacket,
  rules: FirewallRule[],
  address_lists: Record<string, AddressList>,
  signal?: AbortSignal
): Promise<SimulationResult> {
  const res = await fetch(`${API_BASE}/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ packet, rules, address_lists }),
    signal
  });
  if (!res.ok) throw new Error(`Falha na simulação: ${res.statusText}`);
  return res.json();
}

export async function importRulesApi(
  content: string,
  syntax: string = 'auto'
): Promise<{
  detected_syntax: string;
  rules: FirewallRule[];
  address_lists: Record<string, AddressList>;
  rules_count: number;
  address_lists_count: number;
  warnings: string[];
}> {
  const res = await fetch(`${API_BASE}/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, syntax })
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Falha na importação: ${res.statusText}`);
  }
  return res.json();
}

export async function exportRulesApi(
  syntax: string,
  rules: FirewallRule[],
  address_lists: Record<string, AddressList>
): Promise<{ syntax: string; content: string }> {
  const res = await fetch(`${API_BASE}/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ syntax, rules, address_lists })
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Falha na exportação: ${res.statusText}`);
  }
  return res.json();
}
