import { FirewallRule, AddressList, SimulationPacket, SimulationResult } from '../types';

const API_BASE = '/api';

export async function fetchPreset(name: string): Promise<{ rules: FirewallRule[]; address_lists: Record<string, AddressList> }> {
  const res = await fetch(`${API_BASE}/presets/${name}`);
  if (!res.ok) throw new Error(`Falha ao carregar preset: ${res.statusText}`);
  return res.json();
}

export async function runSimulation(
  packet: SimulationPacket,
  rules: FirewallRule[],
  address_lists: Record<string, AddressList>
): Promise<SimulationResult> {
  const res = await fetch(`${API_BASE}/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ packet, rules, address_lists })
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
