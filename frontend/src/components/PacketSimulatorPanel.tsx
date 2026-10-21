import React from 'react';
import { Play, Sparkles, Network, ArrowRight, Activity, RotateCcw } from 'lucide-react';
import { SimulationPacket } from '../types';

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

        {/* Packet Presets */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
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
          <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
            Origem (Source)
          </span>
          <div>
            <label className="text-slate-400 block mb-1">IP de Origem</label>
            <input
              type="text"
              value={packet.src_ip}
              onChange={(e) => updateField('src_ip', e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              placeholder="Ex: 192.168.88.50"
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1 flex items-center justify-between">
              <span>Porta de Origem</span>
              {!isPortApplicable && (
                <span className="text-[10px] text-amber-400/80 font-mono">N/A ({packet.protocol.toUpperCase()})</span>
              )}
            </label>
            <input
              type="number"
              disabled={!isPortApplicable}
              value={isPortApplicable ? (packet.src_port || '') : ''}
              onChange={(e) => updateField('src_port', parseInt(e.target.value) || 0)}
              className={`w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none transition ${
                !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950/80 text-slate-500 border-slate-800' : ''
              }`}
              placeholder={isPortApplicable ? "Ex: 51234" : "Sem porta"}
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1">In-Interface / List</label>
            <input
              type="text"
              value={packet.in_interface || ''}
              onChange={(e) => updateField('in_interface', e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              placeholder="Ex: ether2, LAN ou ether1, WAN"
              title="Aceita interface física (ether1), lista (WAN, LAN) ou ambos (ether1, WAN)"
            />
          </div>
        </div>

        {/* Destination */}
        <div className="space-y-2 p-3 bg-slate-950/60 rounded-xl border border-slate-800/60">
          <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider block">
            Destino (Destination)
          </span>
          <div>
            <label className="text-slate-400 block mb-1">IP de Destino</label>
            <input
              type="text"
              value={packet.dst_ip}
              onChange={(e) => updateField('dst_ip', e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-emerald-500 focus:outline-none"
              placeholder="Ex: 8.8.8.8"
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1 flex items-center justify-between">
              <span>Porta de Destino</span>
              {!isPortApplicable && (
                <span className="text-[10px] text-amber-400/80 font-mono">N/A ({packet.protocol.toUpperCase()})</span>
              )}
            </label>
            <input
              type="number"
              disabled={!isPortApplicable}
              value={isPortApplicable ? (packet.dst_port || '') : ''}
              onChange={(e) => updateField('dst_port', parseInt(e.target.value) || 0)}
              className={`w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-emerald-500 focus:outline-none transition ${
                !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950/80 text-slate-500 border-slate-800' : ''
              }`}
              placeholder={isPortApplicable ? "Ex: 80 / 443" : "Sem porta"}
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1">Out-Interface / List</label>
            <input
              type="text"
              value={packet.out_interface || ''}
              onChange={(e) => updateField('out_interface', e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 font-mono focus:border-emerald-500 focus:outline-none"
              placeholder="Ex: ether1, WAN ou eth0"
              title="Aceita interface física (ether1), lista (WAN, LAN) ou ambos (ether1, WAN)"
            />
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
              onClick={onSimulate}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-medium rounded-lg shadow-lg shadow-cyan-950/50 transition disabled:opacity-50 cursor-pointer"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{loading ? 'Simulando...' : 'Simular Pacote'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
