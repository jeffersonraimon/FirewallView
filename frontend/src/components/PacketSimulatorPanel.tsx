import React, { useState, useEffect, useRef } from 'react';
import { Play, Sparkles, Activity, RotateCcw, ArrowLeftRight, History, Trash2, X } from 'lucide-react';
import { SimulationPacket } from '../types';

const STORAGE_KEY_INPUT_HISTORY = 'firewallview_input_history_v1';

interface InputHistory {
  ips: string[];
  ports: number[];
  interfaces: string[];
}

const DEFAULT_HISTORY: InputHistory = {
  ips: [
    '192.168.88.100',
    '192.168.88.1',
    '10.5.5.5',
    '142.250.190.46',
    '8.8.8.8'
  ],
  ports: [80, 443, 22, 53, 8080, 54321, 51234],
  interfaces: ['ether1-wan', 'ether2-lan', 'ether1', 'ether2', 'WAN', 'LAN']
};

const getStoredHistory = (): InputHistory => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_INPUT_HISTORY);
    if (!raw) return DEFAULT_HISTORY;
    const parsed = JSON.parse(raw);
    return {
      ips: Array.isArray(parsed.ips) && parsed.ips.length ? parsed.ips : DEFAULT_HISTORY.ips,
      ports: Array.isArray(parsed.ports) && parsed.ports.length ? parsed.ports : DEFAULT_HISTORY.ports,
      interfaces: Array.isArray(parsed.interfaces) && parsed.interfaces.length ? parsed.interfaces : DEFAULT_HISTORY.interfaces
    };
  } catch {
    return DEFAULT_HISTORY;
  }
};

interface PacketSimulatorPanelProps {
  packet: SimulationPacket;
  onChangePacket: (newPacket: SimulationPacket) => void;
  onSimulate: () => void;
  autoSimulate: boolean;
  onToggleAutoSimulate: () => void;
  loading: boolean;
}

export const PacketSimulatorPanel: React.FC<PacketSimulatorPanelProps> = ({
  packet,
  onChangePacket,
  onSimulate,
  autoSimulate,
  onToggleAutoSimulate,
  loading
}) => {
  const isTcp = packet.protocol.toLowerCase() === 'tcp';
  const isPortApplicable = ['tcp', 'udp'].includes(packet.protocol.toLowerCase());
  const flowType = packet.flow_type || (packet.is_router_traffic ? 'input' : 'forward');
  const isInputFlow = flowType === 'input';
  const isOutputFlow = flowType === 'output';

  const [history, setHistory] = useState<InputHistory>(getStoredHistory);
  const [activeHistoryMenu, setActiveHistoryMenu] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setActiveHistoryMenu(null);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setActiveHistoryMenu(null);
      }
    };
    if (activeHistoryMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [activeHistoryMenu]);

  const saveToHistory = (
    type: 'ips' | 'ports' | 'interfaces',
    value: string | number | undefined | null
  ) => {
    if (value === undefined || value === null || value === '' || value === 0) return;

    setHistory((prev) => {
      if (type === 'ports') {
        const numVal = typeof value === 'number' ? value : parseInt(String(value), 10);
        if (isNaN(numVal) || numVal <= 0 || numVal > 65535) return prev;
        const nextPorts = [numVal, ...prev.ports.filter((p) => p !== numVal)].slice(0, 20);
        const updated = { ...prev, ports: nextPorts };
        localStorage.setItem(STORAGE_KEY_INPUT_HISTORY, JSON.stringify(updated));
        return updated;
      } else {
        const strVal = String(value).trim();
        if (!strVal) return prev;
        const currentList = prev[type] as string[];
        const nextList = [strVal, ...currentList.filter((item) => item.toLowerCase() !== strVal.toLowerCase())].slice(0, 20);
        const updated = { ...prev, [type]: nextList };
        localStorage.setItem(STORAGE_KEY_INPUT_HISTORY, JSON.stringify(updated));
        return updated;
      }
    });
  };

  const removeFromHistory = (type: 'ips' | 'ports' | 'interfaces', value: string | number) => {
    setHistory((prev) => {
      let updated: InputHistory;
      if (type === 'ports') {
        updated = { ...prev, ports: prev.ports.filter((p) => p !== value) };
      } else {
        updated = { ...prev, [type]: (prev[type] as string[]).filter((item) => item !== value) };
      }
      localStorage.setItem(STORAGE_KEY_INPUT_HISTORY, JSON.stringify(updated));
      return updated;
    });
  };

  const clearCategoryHistory = (type: 'ips' | 'ports' | 'interfaces') => {
    setHistory((prev) => {
      const updated = { ...prev, [type]: [] };
      localStorage.setItem(STORAGE_KEY_INPUT_HISTORY, JSON.stringify(updated));
      return updated;
    });
  };

  const savePacketToHistory = (pkt: SimulationPacket) => {
    if (pkt.src_ip) saveToHistory('ips', pkt.src_ip);
    if (pkt.dst_ip) saveToHistory('ips', pkt.dst_ip);
    if (pkt.src_port && pkt.src_port > 0) saveToHistory('ports', pkt.src_port);
    if (pkt.dst_port && pkt.dst_port > 0) saveToHistory('ports', pkt.dst_port);
    if (pkt.in_interface) saveToHistory('interfaces', pkt.in_interface);
    if (pkt.out_interface) saveToHistory('interfaces', pkt.out_interface);
  };

  const handleSwapSrcDst = () => {
    let newFlowType = packet.flow_type || (packet.is_router_traffic ? 'input' : 'forward');
    let newIsRouter = packet.is_router_traffic;

    let newInInterface = packet.out_interface;
    let newOutInterface = packet.in_interface;

    if (newFlowType === 'input') {
      newFlowType = 'output';
      newIsRouter = true;
      newOutInterface = packet.in_interface;
      newInInterface = '';
    } else if (newFlowType === 'output') {
      newFlowType = 'input';
      newIsRouter = true;
      newInInterface = packet.out_interface;
      newOutInterface = '';
    } else {
      newInInterface = packet.out_interface;
      newOutInterface = packet.in_interface;
    }

    const updated: SimulationPacket = {
      ...packet,
      src_ip: packet.dst_ip,
      dst_ip: packet.src_ip,
      src_port: packet.dst_port,
      dst_port: packet.src_port,
      in_interface: newInInterface,
      out_interface: newOutInterface,
      flow_type: newFlowType,
      is_router_traffic: newIsRouter
    };

    savePacketToHistory(packet);
    savePacketToHistory(updated);
    onChangePacket(updated);
  };

  const handleSimulate = () => {
    savePacketToHistory(packet);
    onSimulate();
  };

  const renderHistoryDropdown = (
    menuId: string,
    category: 'ips' | 'ports' | 'interfaces',
    items: (string | number)[],
    onSelect: (val: any) => void,
    title: string
  ) => {
    if (activeHistoryMenu !== menuId) return null;
    return (
      <div
        ref={dropdownRef}
        className="absolute right-0 top-full mt-1 w-64 max-w-[90vw] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl z-50 p-1.5 text-xs animate-in fade-in zoom-in-95"
      >
        <div className="flex items-center justify-between px-2 py-1 border-b border-slate-800 text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
          <span className="flex items-center gap-1">
            <History className="w-3 h-3 text-cyan-400" />
            {title}
          </span>
          {items.length > 0 && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                clearCategoryHistory(category);
              }}
              className="text-rose-400 hover:text-rose-300 hover:underline flex items-center gap-0.5 normal-case font-normal"
              title="Limpar histórico deste campo"
            >
              <Trash2 className="w-2.5 h-2.5" /> Limpar
            </button>
          )}
        </div>
        <div className="max-h-40 overflow-y-auto py-1 space-y-0.5">
          {items.length === 0 ? (
            <div className="px-2 py-2 text-center text-slate-500 text-[11px] italic">
              Nenhum item recente
            </div>
          ) : (
            items.map((item) => (
              <div
                key={String(item)}
                onClick={() => {
                  onSelect(item);
                  setActiveHistoryMenu(null);
                }}
                className="group flex items-center justify-between px-2 py-1 rounded-lg hover:bg-slate-800 cursor-pointer text-slate-200 transition"
              >
                <span className="font-mono text-[11px] truncate">{item}</span>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    removeFromHistory(category, item);
                  }}
                  className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-rose-400 p-0.5 rounded transition"
                  title="Remover"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    );
  };

  const handleProtocolChange = (newProto: string) => {
    const updated: SimulationPacket = {
      ...packet,
      protocol: newProto
    };
    if (newProto.toLowerCase() !== 'tcp') {
      updated.tcp_flags = [];
    }
    if (!['tcp', 'udp'].includes(newProto.toLowerCase())) {
      updated.src_port = 0;
      updated.dst_port = 0;
    }
    onChangePacket(updated);
  };

  const updateField = (field: keyof SimulationPacket, value: any) => {
    onChangePacket({
      ...packet,
      [field]: value
    });
  };

  const setPacketPreset = (presetType: string) => {
    switch (presetType) {
      case 'lan_http':
        onChangePacket({
          src_ip: '192.168.88.100',
          dst_ip: '142.250.190.46',
          src_port: 54321,
          dst_port: 80,
          protocol: 'tcp',
          in_interface: 'ether2-lan',
          out_interface: 'ether1-wan',
          connection_state: 'new',
          tcp_flags: ['syn'],
          packet_marks: [],
          flow_type: 'forward',
          is_router_traffic: false
        });
        break;
      case 'admin_ssh':
        onChangePacket({
          src_ip: '192.168.88.5',
          dst_ip: '192.168.88.1',
          src_port: 51234,
          dst_port: 22,
          protocol: 'tcp',
          in_interface: 'ether2-lan',
          out_interface: '',
          connection_state: 'new',
          tcp_flags: ['syn'],
          packet_marks: [],
          flow_type: 'input',
          is_router_traffic: true
        });
        break;
      case 'bogon_attack':
        onChangePacket({
          src_ip: '10.5.5.5',
          dst_ip: '192.168.88.50',
          src_port: 44444,
          dst_port: 80,
          protocol: 'tcp',
          in_interface: 'ether1-wan',
          out_interface: 'ether2-lan',
          connection_state: 'new',
          tcp_flags: ['syn'],
          packet_marks: [],
          flow_type: 'forward',
          is_router_traffic: false
        });
        break;
      case 'port_forward_test':
        onChangePacket({
          src_ip: '200.180.50.12',
          dst_ip: '203.0.113.1',
          src_port: 48999,
          dst_port: 8080,
          protocol: 'tcp',
          in_interface: 'ether1-wan',
          out_interface: 'ether2-lan',
          connection_state: 'new',
          tcp_flags: ['syn'],
          packet_marks: [],
          flow_type: 'forward',
          is_router_traffic: false
        });
        break;
      case 'icmp_ping':
        onChangePacket({
          src_ip: '192.168.88.10',
          dst_ip: '192.168.88.1',
          src_port: 0,
          dst_port: 0,
          protocol: 'icmp',
          in_interface: 'ether2-lan',
          out_interface: '',
          connection_state: 'new',
          tcp_flags: [],
          packet_marks: [],
          flow_type: 'input',
          is_router_traffic: true
        });
        break;
      case 'router_output':
        onChangePacket({
          src_ip: '192.168.88.1',
          dst_ip: '8.8.8.8',
          src_port: 49500,
          dst_port: 53,
          protocol: 'udp',
          in_interface: '',
          out_interface: 'ether1-wan',
          connection_state: 'new',
          tcp_flags: [],
          packet_marks: [],
          flow_type: 'output',
          is_router_traffic: true
        });
        break;
      case 'clear':
        onChangePacket({
          src_ip: '',
          dst_ip: '',
          src_port: 0,
          dst_port: 0,
          protocol: 'tcp',
          in_interface: '',
          out_interface: '',
          connection_state: 'new',
          tcp_flags: [],
          packet_marks: [],
          flow_type: 'forward',
          is_router_traffic: false
        });
        break;
      default:
        break;
    }
  };

  const toggleFlag = (flag: string) => {
    const flags = [...packet.tcp_flags];
    const idx = flags.indexOf(flag);
    if (idx >= 0) {
      flags.splice(idx, 1);
    } else {
      flags.push(flag);
    }
    updateField('tcp_flags', flags);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-xl mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
            Injetor de Pacote de Teste
          </h2>
        </div>

        {/* Packet Presets and Swap Actions */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <button
            type="button"
            onClick={handleSwapSrcDst}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950/60 border border-slate-700/80 hover:border-cyan-500/60 text-cyan-300 hover:text-cyan-200 transition flex items-center gap-1.5 font-medium shadow-sm"
            title="Inverter Origem e Destino (IPs, Portas e Interfaces)"
          >
            <ArrowLeftRight className="w-3.5 h-3.5 text-cyan-400" />
            <span>Inverter Origem ⇄ Destino</span>
          </button>
          <span className="text-slate-600 hidden sm:inline">|</span>
          <span className="text-slate-400 text-[11px] font-medium mr-1 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-amber-400" /> Testes Rápidos:
          </span>
          <button
            onClick={() => setPacketPreset('lan_http')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            LAN → Web (80)
          </button>
          <button
            onClick={() => setPacketPreset('admin_ssh')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            Admin SSH (Router)
          </button>
          <button
            onClick={() => setPacketPreset('bogon_attack')}
            className="px-2 py-1 rounded bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800/60 text-rose-300 transition"
          >
            Ataque Bogon WAN
          </button>
          <button
            onClick={() => setPacketPreset('port_forward_test')}
            className="px-2 py-1 rounded bg-amber-950/60 hover:bg-amber-900/80 border border-amber-800/60 text-amber-300 transition"
          >
            Port Forward (8080)
          </button>
          <button
            onClick={() => setPacketPreset('icmp_ping')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            Ping ICMP
          </button>
          <button
            onClick={() => setPacketPreset('router_output')}
            className="px-2 py-1 rounded bg-purple-950/60 hover:bg-purple-900/80 border border-purple-800/60 text-purple-300 transition"
            title="Pacote originado no próprio roteador saindo para a internet (OUTPUT)"
          >
            Router Output (DNS 53)
          </button>
          <button
            onClick={() => setPacketPreset('clear')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-rose-950/40 border border-slate-700/60 hover:border-rose-800/50 text-slate-400 hover:text-rose-300 transition flex items-center gap-1"
            title="Limpar todos os campos do pacote de teste"
          >
            <RotateCcw className="w-3 h-3" />
            Limpar
          </button>
        </div>
      </div>

      {/* Inputs Form */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
        {/* Source */}
        <div className="space-y-2 p-3 bg-slate-950/60 rounded-xl border border-slate-800/60">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
              Origem (Source)
            </span>
            <button
              type="button"
              onClick={handleSwapSrcDst}
              className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 hover:bg-cyan-950/60 border border-slate-700/60 hover:border-cyan-500/40 text-[10px] text-cyan-300 transition"
              title="Inverter Origem ⇄ Destino"
            >
              <ArrowLeftRight className="w-3 h-3 text-cyan-400" />
              <span>Inverter</span>
            </button>
          </div>
          <div>
            <label className="text-slate-400 block mb-1">IP de Origem</label>
            <div className="relative">
              <input
                type="text"
                list="history-ips"
                value={packet.src_ip}
                onChange={(e) => updateField('src_ip', e.target.value)}
                onBlur={() => saveToHistory('ips', packet.src_ip)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-2.5 pr-8 py-1.5 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                placeholder="Ex: 192.168.88.50"
              />
              <button
                type="button"
                onClick={() => setActiveHistoryMenu(activeHistoryMenu === 'src_ip' ? null : 'src_ip')}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 rounded transition"
                title="Histórico recente de IPs"
              >
                <History className="w-3.5 h-3.5" />
              </button>
              {renderHistoryDropdown(
                'src_ip',
                'ips',
                history.ips,
                (val) => updateField('src_ip', val),
                'IPs Recentes'
              )}
            </div>
          </div>
          <div>
            <label className="text-slate-400 block mb-1 flex items-center justify-between">
              <span>Porta de Origem</span>
              {!isPortApplicable && (
                <span className="text-[10px] text-amber-400/80 font-mono">N/A ({packet.protocol.toUpperCase()})</span>
              )}
            </label>
            <div className="relative">
              <input
                type="number"
                list="history-ports"
                disabled={!isPortApplicable}
                value={isPortApplicable ? (packet.src_port || '') : ''}
                onChange={(e) => updateField('src_port', parseInt(e.target.value) || 0)}
                onBlur={() => saveToHistory('ports', packet.src_port)}
                className={`w-full bg-slate-900 border border-slate-700 rounded-lg pl-2.5 pr-8 py-1.5 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none transition ${
                  !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950/80 text-slate-500 border-slate-800' : ''
                }`}
                placeholder={isPortApplicable ? "Ex: 51234" : "Sem porta"}
              />
              {isPortApplicable && (
                <button
                  type="button"
                  onClick={() => setActiveHistoryMenu(activeHistoryMenu === 'src_port' ? null : 'src_port')}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 rounded transition"
                  title="Histórico recente de Portas"
                >
                  <History className="w-3.5 h-3.5" />
                </button>
              )}
              {renderHistoryDropdown(
                'src_port',
                'ports',
                history.ports,
                (val) => updateField('src_port', Number(val)),
                'Portas Recentes'
              )}
            </div>
          </div>
          <div>
            <label className="text-slate-400 block mb-1 flex items-center justify-between">
              <span>{isOutputFlow ? 'Out-Interface / List' : 'In-Interface / List'}</span>
              <span className="text-[10px] text-cyan-400/80 font-mono">
                {isOutputFlow ? 'Saída Roteador' : 'Entrada'}
              </span>
            </label>
            <div className="relative">
              <input
                type="text"
                list="history-interfaces"
                value={(isOutputFlow ? packet.out_interface : packet.in_interface) || ''}
                onChange={(e) => updateField(isOutputFlow ? 'out_interface' : 'in_interface', e.target.value)}
                onBlur={() => saveToHistory('interfaces', isOutputFlow ? packet.out_interface : packet.in_interface)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-2.5 pr-8 py-1.5 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                placeholder={isOutputFlow ? "Ex: ether1, WAN ou eth0" : "Ex: ether2, LAN ou ether1, WAN"}
                title="Interface física ou lista de interface (ex: WAN, LAN)"
              />
              <button
                type="button"
                onClick={() => setActiveHistoryMenu(activeHistoryMenu === 'src_iface' ? null : 'src_iface')}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 rounded transition"
                title="Histórico recente de Interfaces"
              >
                <History className="w-3.5 h-3.5" />
              </button>
              {renderHistoryDropdown(
                'src_iface',
                'interfaces',
                history.interfaces,
                (val) => updateField(isOutputFlow ? 'out_interface' : 'in_interface', val),
                'Interfaces Recentes'
              )}
            </div>
          </div>
        </div>

        {/* Destination */}
        <div className="space-y-2 p-3 bg-slate-950/60 rounded-xl border border-slate-800/60">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider block">
              Destino (Destination)
            </span>
            <button
              type="button"
              onClick={handleSwapSrcDst}
              className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 hover:bg-emerald-950/60 border border-slate-700/60 hover:border-emerald-500/40 text-[10px] text-emerald-300 transition"
              title="Inverter Origem ⇄ Destino"
            >
              <ArrowLeftRight className="w-3 h-3 text-emerald-400" />
              <span>Inverter</span>
            </button>
          </div>
          <div>
            <label className="text-slate-400 block mb-1">IP de Destino</label>
            <div className="relative">
              <input
                type="text"
                list="history-ips"
                value={packet.dst_ip}
                onChange={(e) => updateField('dst_ip', e.target.value)}
                onBlur={() => saveToHistory('ips', packet.dst_ip)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-2.5 pr-8 py-1.5 text-slate-100 font-mono focus:border-emerald-500 focus:outline-none"
                placeholder="Ex: 8.8.8.8"
              />
              <button
                type="button"
                onClick={() => setActiveHistoryMenu(activeHistoryMenu === 'dst_ip' ? null : 'dst_ip')}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-emerald-400 hover:bg-slate-800 rounded transition"
                title="Histórico recente de IPs"
              >
                <History className="w-3.5 h-3.5" />
              </button>
              {renderHistoryDropdown(
                'dst_ip',
                'ips',
                history.ips,
                (val) => updateField('dst_ip', val),
                'IPs Recentes'
              )}
            </div>
          </div>
          <div>
            <label className="text-slate-400 block mb-1 flex items-center justify-between">
              <span>Porta de Destino</span>
              {!isPortApplicable && (
                <span className="text-[10px] text-amber-400/80 font-mono">N/A ({packet.protocol.toUpperCase()})</span>
              )}
            </label>
            <div className="relative">
              <input
                type="number"
                list="history-ports"
                disabled={!isPortApplicable}
                value={isPortApplicable ? (packet.dst_port || '') : ''}
                onChange={(e) => updateField('dst_port', parseInt(e.target.value) || 0)}
                onBlur={() => saveToHistory('ports', packet.dst_port)}
                className={`w-full bg-slate-900 border border-slate-700 rounded-lg pl-2.5 pr-8 py-1.5 text-slate-100 font-mono focus:border-emerald-500 focus:outline-none transition ${
                  !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950/80 text-slate-500 border-slate-800' : ''
                }`}
                placeholder={isPortApplicable ? "Ex: 80 / 443" : "Sem porta"}
              />
              {isPortApplicable && (
                <button
                  type="button"
                  onClick={() => setActiveHistoryMenu(activeHistoryMenu === 'dst_port' ? null : 'dst_port')}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-emerald-400 hover:bg-slate-800 rounded transition"
                  title="Histórico recente de Portas"
                >
                  <History className="w-3.5 h-3.5" />
                </button>
              )}
              {renderHistoryDropdown(
                'dst_port',
                'ports',
                history.ports,
                (val) => updateField('dst_port', Number(val)),
                'Portas Recentes'
              )}
            </div>
          </div>
          <div>
            <label className="text-slate-400 block mb-1 flex items-center justify-between">
              <span>{isInputFlow ? 'In-Interface no Roteador' : 'Out-Interface / List'}</span>
              <span className="text-[10px] text-emerald-400 font-mono">
                {isInputFlow ? 'Destino (Local)' : 'Saída'}
              </span>
            </label>
            <div className="relative">
              <input
                type="text"
                list="history-interfaces"
                value={(isInputFlow ? packet.in_interface : packet.out_interface) || ''}
                onChange={(e) => {
                  const val = e.target.value;
                  if (isInputFlow) {
                    onChangePacket({
                      ...packet,
                      in_interface: val,
                      out_interface: ''
                    });
                  } else {
                    updateField('out_interface', val);
                  }
                }}
                onBlur={() => saveToHistory('interfaces', isInputFlow ? packet.in_interface : packet.out_interface)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-2.5 pr-8 py-1.5 text-slate-100 font-mono focus:border-emerald-500 focus:outline-none"
                placeholder={isInputFlow ? "Ex: WAN, ether1 ou ether1, WAN" : "Ex: ether1, WAN ou eth0"}
                title={isInputFlow ? "Interface por onde o pacote chega ao roteador (In-Interface)" : "Interface por onde o pacote sai (Out-Interface)"}
              />
              <button
                type="button"
                onClick={() => setActiveHistoryMenu(activeHistoryMenu === 'dst_iface' ? null : 'dst_iface')}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-emerald-400 hover:bg-slate-800 rounded transition"
                title="Histórico recente de Interfaces"
              >
                <History className="w-3.5 h-3.5" />
              </button>
              {renderHistoryDropdown(
                'dst_iface',
                'interfaces',
                history.interfaces,
                (val) => {
                  if (isInputFlow) {
                    onChangePacket({
                      ...packet,
                      in_interface: val,
                      out_interface: ''
                    });
                  } else {
                    updateField('out_interface', val);
                  }
                },
                'Interfaces Recentes'
              )}
            </div>
          </div>
        </div>

        {/* Protocol & State */}
        <div className="space-y-2 p-3 bg-slate-950/60 rounded-xl border border-slate-800/60">
          <span className="text-[11px] font-semibold text-violet-400 uppercase tracking-wider block">
            Protocolo & Conexão
          </span>
          <div>
            <label className="text-slate-400 block mb-1">Protocolo</label>
            <select
              value={packet.protocol}
              onChange={(e) => handleProtocolChange(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-violet-500 focus:outline-none"
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
              <option value="gre">GRE</option>
              <option value="esp">ESP</option>
            </select>
          </div>
          <div>
            <label className="text-slate-400 block mb-1">Connection State</label>
            <select
              value={packet.connection_state}
              onChange={(e) => updateField('connection_state', e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-violet-500 focus:outline-none"
            >
              <option value="new">new</option>
              <option value="established">established</option>
              <option value="related">related</option>
              <option value="invalid">invalid</option>
              <option value="untracked">untracked</option>
            </select>
          </div>
          <div>
            <label className="text-slate-400 block mb-1">Fluxo do Roteador</label>
            <div className="grid grid-cols-3 gap-1">
              <button
                type="button"
                onClick={() => {
                  onChangePacket({
                    ...packet,
                    flow_type: 'forward',
                    is_router_traffic: false
                  });
                }}
                className={`py-1 px-1 rounded text-center transition font-medium text-[11px] truncate ${
                  (packet.flow_type || (packet.is_router_traffic ? 'input' : 'forward')) === 'forward'
                    ? 'bg-cyan-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
                title="Tráfego passando pelo roteador (PREROUTING -> FORWARD -> POSTROUTING)"
              >
                Forward
              </button>
              <button
                type="button"
                onClick={() => {
                  onChangePacket({
                    ...packet,
                    flow_type: 'input',
                    is_router_traffic: true
                  });
                }}
                className={`py-1 px-1 rounded text-center transition font-medium text-[11px] truncate ${
                  (packet.flow_type || (packet.is_router_traffic ? 'input' : 'forward')) === 'input'
                    ? 'bg-amber-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
                title="Tráfego destinado ao roteador (PREROUTING -> INPUT)"
              >
                Input
              </button>
              <button
                type="button"
                onClick={() => {
                  onChangePacket({
                    ...packet,
                    flow_type: 'output',
                    is_router_traffic: true
                  });
                }}
                className={`py-1 px-1 rounded text-center transition font-medium text-[11px] truncate ${
                  packet.flow_type === 'output'
                    ? 'bg-purple-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
                title="Tráfego originado localmente no roteador (OUTPUT -> POSTROUTING)"
              >
                Output
              </button>
            </div>
          </div>
        </div>

        {/* TCP Flags & Actions */}
        <div className="space-y-3 p-3 bg-slate-950/60 rounded-xl border border-slate-800/60 flex flex-col justify-between">
          {/* Flags section (disabled when not TCP) */}
          <div className={`transition ${!isTcp ? 'opacity-40' : ''}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider block">
                TCP Flags
              </span>
              {!isTcp && (
                <span className="text-[10px] text-slate-500 font-mono italic">Apenas TCP</span>
              )}
            </div>
            <div className={`grid grid-cols-3 gap-1.5 ${!isTcp ? 'pointer-events-none' : ''}`}>
              {['syn', 'ack', 'fin', 'rst', 'psh', 'urg'].map((flag) => {
                const active = isTcp && packet.tcp_flags.includes(flag);
                return (
                  <button
                    key={flag}
                    type="button"
                    disabled={!isTcp}
                    onClick={() => toggleFlag(flag)}
                    className={`py-1 text-center uppercase font-mono text-[11px] rounded transition ${
                      active
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                        : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200 disabled:opacity-40 disabled:hover:bg-slate-800'
                    }`}
                  >
                    {flag}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Simulation Action Controls (always active) */}
          <div className="pt-2 border-t border-slate-800/80 flex flex-col gap-2">
            <label className="flex items-center gap-2 cursor-pointer text-slate-400 hover:text-slate-200 select-none">
              <input
                type="checkbox"
                checked={autoSimulate}
                onChange={onToggleAutoSimulate}
                className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
              />
              <span>Simulação Automática</span>
            </label>

            <button
              onClick={handleSimulate}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-medium rounded-lg shadow-lg shadow-cyan-950/50 transition disabled:opacity-50 cursor-pointer"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{loading ? 'Simulando...' : 'Simular Pacote'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* HTML5 Datalists for native browser autocomplete suggestions */}
      <datalist id="history-ips">
        {history.ips.map((ip) => (
          <option key={`dl-ip-${ip}`} value={ip} />
        ))}
      </datalist>
      <datalist id="history-ports">
        {history.ports.map((port) => (
          <option key={`dl-port-${port}`} value={port} />
        ))}
      </datalist>
      <datalist id="history-interfaces">
        {history.interfaces.map((iface) => (
          <option key={`dl-iface-${iface}`} value={iface} />
        ))}
      </datalist>
    </div>
  );
};
