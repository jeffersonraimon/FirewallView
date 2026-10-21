import React, { useState, useEffect } from 'react';
import { X, Save, Plus, Shield, Layers, HelpCircle } from 'lucide-react';
import { FirewallRule, AddressList } from '../types';

interface RuleEditorModalProps {
  isOpen: boolean;
  onClose: () => void;
  ruleToEdit: FirewallRule | null;
  onSaveRule: (rule: FirewallRule) => void;
  addressLists: Record<string, AddressList>;
  currentSyntax?: string;
}

export const RuleEditorModal: React.FC<RuleEditorModalProps> = ({
  isOpen,
  onClose,
  ruleToEdit,
  onSaveRule,
  addressLists,
  currentSyntax = 'routeros'
}) => {
  const [selectedSyntax, setSelectedSyntax] = useState<string>(currentSyntax);
  const [table, setTable] = useState('filter');
  const [chain, setChain] = useState('forward');
  const [isCustomChain, setIsCustomChain] = useState(false);
  const [action, setAction] = useState('accept');
  const [targetChain, setTargetChain] = useState('');
  const [natAddresses, setNatAddresses] = useState('');
  const [natPorts, setNatPorts] = useState('');
  const [comment, setComment] = useState('');

  // Matchers
  const [protocol, setProtocol] = useState('');
  const [srcAddress, setSrcAddress] = useState('');
  const [dstAddress, setDstAddress] = useState('');
  const [srcList, setSrcList] = useState('');
  const [dstList, setDstList] = useState('');
  const [srcPort, setSrcPort] = useState('');
  const [dstPort, setDstPort] = useState('');
  const [anyPort, setAnyPort] = useState('');
  const [inIface, setInIface] = useState('');
  const [outIface, setOutIface] = useState('');
  const [connStates, setConnStates] = useState<string[]>([]);

  const isPortApplicable = !protocol || ['tcp', 'udp', 'any', ''].includes(protocol.trim().toLowerCase());

  // Configuration definitions by manufacturer
  const manufacturerConfigs: Record<string, any> = {
    routeros: {
      name: 'MikroTik RouterOS',
      icon: '⚡',
      tableLabel: 'Tabela (/ip firewall)',
      tables: [
        { value: 'filter', label: 'filter (Filtragem)' },
        { value: 'nat', label: 'nat (Tradução de Endereço)' },
        { value: 'mangle', label: 'mangle (QoS e Marcações)' },
        { value: 'raw', label: 'raw (Pre-Connection Tracking)' },
      ],
      chainsForTable: {
        filter: ['forward', 'input', 'output'],
        nat: ['srcnat', 'dstnat'],
        mangle: ['prerouting', 'forward', 'input', 'output', 'postrouting'],
        raw: ['prerouting', 'output'],
      },
      actions: [
        { value: 'accept', label: 'accept (Permitir)' },
        { value: 'drop', label: 'drop (Bloquear/Descartar)' },
        { value: 'reject', label: 'reject (Rejeitar com ICMP)' },
        { value: 'fasttrack-connection', label: 'fasttrack-connection (Hardware Fastpath)' },
        { value: 'dst-nat', label: 'dst-nat (Port Forwarding)' },
        { value: 'src-nat', label: 'src-nat (SNAT manual)' },
        { value: 'masquerade', label: 'masquerade (NAT Dinâmico)' },
        { value: 'redirect', label: 'redirect (Redirecionar p/ Router)' },
        { value: 'jump', label: 'jump (Pular para Chain customizada)' },
        { value: 'return', label: 'return (Voltar da Chain)' },
        { value: 'log', label: 'log (Registrar no log)' },
      ],
      listLabel: 'Address List',
      chainLabel: 'Chain',
      commentLabel: 'Comentário (comment=)',
    },
    iptables: {
      name: 'Linux iptables & ipset',
      icon: '🐧',
      tableLabel: 'Tabela (-t)',
      tables: [
        { value: 'filter', label: 'filter (Padrão)' },
        { value: 'nat', label: 'nat (NAT)' },
        { value: 'mangle', label: 'mangle (Alteração de pacotes)' },
        { value: 'raw', label: 'raw (Bypass de conntrack)' },
      ],
      chainsForTable: {
        filter: ['FORWARD', 'INPUT', 'OUTPUT'],
        nat: ['PREROUTING', 'POSTROUTING', 'OUTPUT'],
        mangle: ['PREROUTING', 'FORWARD', 'INPUT', 'OUTPUT', 'POSTROUTING'],
        raw: ['PREROUTING', 'OUTPUT'],
      },
      actions: [
        { value: 'accept', label: 'ACCEPT (Permitir)' },
        { value: 'drop', label: 'DROP (Descartar)' },
        { value: 'reject', label: 'REJECT (Rejeitar)' },
        { value: 'dst-nat', label: 'DNAT (--to-destination)' },
        { value: 'src-nat', label: 'SNAT (--to-source)' },
        { value: 'masquerade', label: 'MASQUERADE' },
        { value: 'redirect', label: 'REDIRECT' },
        { value: 'jump', label: 'JUMP (-j <chain>)' },
      ],
      listLabel: 'ipset (--match-set)',
      chainLabel: 'Chain (-A)',
      commentLabel: 'Comentário (--comment)',
    },
    nftables: {
      name: 'Linux nftables',
      icon: '🛡️',
      tableLabel: 'Família / Tabela',
      tables: [
        { value: 'filter', label: 'table inet filter' },
        { value: 'nat', label: 'table ip nat' },
        { value: 'mangle', label: 'table inet mangle' },
      ],
      chainsForTable: {
        filter: ['forward', 'input', 'output'],
        nat: ['prerouting', 'postrouting'],
        mangle: ['prerouting', 'forward', 'input', 'output', 'postrouting'],
      },
      actions: [
        { value: 'accept', label: 'accept' },
        { value: 'drop', label: 'drop' },
        { value: 'reject', label: 'reject' },
        { value: 'dst-nat', label: 'dnat to' },
        { value: 'src-nat', label: 'snat to' },
        { value: 'masquerade', label: 'masquerade' },
      ],
      listLabel: 'Set (@nome)',
      chainLabel: 'Chain (Hook)',
      commentLabel: 'Comentário (comment)',
    },
    cisco: {
      name: 'Cisco IOS / ASA',
      icon: '🏢',
      tableLabel: 'Tipo de Política',
      tables: [
        { value: 'filter', label: 'Access Control List (ip access-list)' }
      ],
      chainsForTable: {
        filter: ['WAN_IN', 'LAN_OUT', 'EDGE_FILTER', '101', '100'],
      },
      actions: [
        { value: 'accept', label: 'permit (Permitir)' },
        { value: 'drop', label: 'deny (Bloquear)' },
      ],
      listLabel: 'object-group network',
      chainLabel: 'Nome da ACL (Chain)',
      commentLabel: 'Descrição / Remark',
    },
    junos: {
      name: 'Juniper Junos OS',
      icon: '🌲',
      tableLabel: 'Família de Protocolo',
      tables: [
        { value: 'filter', label: 'firewall family inet (Filtro L3)' }
      ],
      chainsForTable: {
        filter: ['FILTER_INBOUND', 'PROTECT_RE', 'EDGE_FILTER', 'WAN_FILTER'],
      },
      actions: [
        { value: 'accept', label: 'accept (Permitir)' },
        { value: 'drop', label: 'discard (Descarte silencioso)' },
        { value: 'reject', label: 'reject (Rejeitar com ICMP)' },
      ],
      listLabel: 'prefix-list',
      chainLabel: 'Nome do Filtro (filter)',
      commentLabel: 'Nome do Termo (term <nome>)',
    },
    dmos: {
      name: 'Datacom DmOS',
      icon: '🇧🇷',
      tableLabel: 'Tipo de ACL',
      tables: [
        { value: 'filter', label: 'acl-profile cpu l3 / protection' }
      ],
      chainsForTable: {
        filter: ['input', 'ACL-PADRAO-CPU', 'forward'],
      },
      actions: [
        { value: 'accept', label: 'permit (Permitir)' },
        { value: 'drop', label: 'deny (Bloquear)' },
      ],
      listLabel: 'prefix-list',
      chainLabel: 'Perfil / Aplicação (Chain)',
      commentLabel: 'description <comentário>',
    }
  };

  const currentConfig = manufacturerConfigs[selectedSyntax] || manufacturerConfigs.routeros;
  const availableChains = currentConfig.chainsForTable[table] || ['forward', 'input'];

  useEffect(() => {
    if (isOpen) {
      if (ruleToEdit) {
        setSelectedSyntax(currentSyntax);
        setTable(ruleToEdit.table);
        setChain(ruleToEdit.chain);
        setAction(ruleToEdit.action);
        setTargetChain(ruleToEdit.target_chain || '');
        setNatAddresses(ruleToEdit.nat_to_addresses || '');
        setNatPorts(ruleToEdit.nat_to_ports || '');
        setComment(ruleToEdit.comment || '');

        setProtocol(ruleToEdit.conditions.protocol || '');
        setSrcAddress(ruleToEdit.conditions.src_address || '');
        setDstAddress(ruleToEdit.conditions.dst_address || '');
        setSrcList(ruleToEdit.conditions.src_address_list || '');
        setDstList(ruleToEdit.conditions.dst_address_list || '');
        setSrcPort(ruleToEdit.conditions.src_port || '');
        setDstPort(ruleToEdit.conditions.dst_port || '');
        setAnyPort(ruleToEdit.conditions.port || '');
        setInIface(ruleToEdit.conditions.in_interface || '');
        setOutIface(ruleToEdit.conditions.out_interface || '');
        setConnStates(ruleToEdit.conditions.connection_state || []);
      } else {
        setSelectedSyntax(currentSyntax);
        setTable('filter');
        const defaultChains = manufacturerConfigs[currentSyntax]?.chainsForTable?.filter || ['forward'];
        setChain(defaultChains[0] || 'forward');
        setIsCustomChain(false);
        setAction('accept');
        setTargetChain('');
        setNatAddresses('');
        setNatPorts('');
        setComment(currentSyntax === 'junos' ? 'allow-traffic' : '');
        setProtocol('');
        setSrcAddress('');
        setDstAddress('');
        setSrcList('');
        setDstList('');
        setSrcPort('');
        setDstPort('');
        setAnyPort('');
        setInIface('');
        setOutIface('');
        setConnStates([]);
      }
    }
  }, [ruleToEdit, isOpen, currentSyntax]);

  // When user switches manufacturer in modal
  const handleManufacturerChange = (newSyntax: string) => {
    setSelectedSyntax(newSyntax);
    const cfg = manufacturerConfigs[newSyntax];
    const newTable = cfg.tables[0].value;
    setTable(newTable);
    const chains = cfg.chainsForTable[newTable] || ['forward'];
    setChain(chains[0] || 'forward');
    setIsCustomChain(false);
    setAction(cfg.actions[0].value);
  };

  // When user switches table, adjust default chain
  const handleTableChange = (newTable: string) => {
    setTable(newTable);
    const chains = currentConfig.chainsForTable[newTable] || ['forward'];
    if (!chains.includes(chain)) {
      setChain(chains[0] || 'forward');
      setIsCustomChain(false);
    }
  };

  if (!isOpen) return null;

  const handleToggleState = (stateName: string) => {
    if (connStates.includes(stateName)) {
      setConnStates(connStates.filter(s => s !== stateName));
    } else {
      setConnStates([...connStates, stateName]);
    }
  };

  const handleSave = () => {
    const newRule: FirewallRule = {
      id: ruleToEdit ? ruleToEdit.id : Math.random().toString(36).substring(2, 9),
      order: ruleToEdit ? ruleToEdit.order : 999,
      table,
      chain,
      action,
      target_chain: action === 'jump' ? targetChain : undefined,
      nat_to_addresses: ['dst-nat', 'src-nat'].includes(action) ? natAddresses : undefined,
      nat_to_ports: ['dst-nat', 'redirect'].includes(action) ? natPorts : undefined,
      comment: comment.trim() || undefined,
      disabled: ruleToEdit ? ruleToEdit.disabled : false,
      conditions: {
        protocol: protocol.trim() || undefined,
        src_address: srcAddress.trim() || undefined,
        dst_address: dstAddress.trim() || undefined,
        src_address_list: srcList || undefined,
        dst_address_list: dstList || undefined,
        src_port: (isPortApplicable && srcPort.trim()) ? srcPort.trim() : undefined,
        dst_port: (isPortApplicable && dstPort.trim()) ? dstPort.trim() : undefined,
        port: (isPortApplicable && anyPort.trim()) ? anyPort.trim() : undefined,
        in_interface: inIface.trim() || undefined,
        out_interface: outIface.trim() || undefined,
        connection_state: connStates.length > 0 ? connStates : undefined
      }
    };

    onSaveRule(newRule);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-base font-bold text-white">
                {ruleToEdit ? 'Editar Regra de Firewall' : 'Adicionar Nova Regra'}
              </h2>
              <span className="text-xs text-slate-400 font-mono">
                {currentConfig.icon} Sintaxe adaptada: <strong className="text-slate-200">{currentConfig.name}</strong>
              </span>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <div className="p-5 flex-1 overflow-y-auto space-y-4 text-xs font-sans">
          {/* Manufacturer Selector in Modal */}
          <div className="flex items-center justify-between p-2.5 bg-slate-950 rounded-xl border border-slate-800 text-xs">
            <span className="text-slate-400 font-medium">Equipamento / Fabricante:</span>
            <select
              value={selectedSyntax}
              onChange={(e) => handleManufacturerChange(e.target.value)}
              className="bg-slate-900 border border-slate-700 text-cyan-300 font-semibold rounded-lg px-2.5 py-1 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="routeros">⚡ MikroTik RouterOS</option>
              <option value="iptables">🐧 Linux iptables & ipset</option>
              <option value="nftables">🛡️ Linux nftables</option>
              <option value="cisco">🏢 Cisco IOS / ASA</option>
              <option value="junos">🌲 Juniper Junos OS</option>
              <option value="dmos">🇧🇷 Datacom DmOS</option>
            </select>
          </div>

          {/* Section 1: Table, Chain, Action (Dynamic according to selected platform) */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 bg-slate-950/70 rounded-xl border border-slate-800">
            {/* Table */}
            <div>
              <label className="text-slate-400 block mb-1 font-medium">{currentConfig.tableLabel}</label>
              <select
                value={table}
                onChange={(e) => handleTableChange(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              >
                {currentConfig.tables.map((t: any) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>

            {/* Chain */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-slate-400 font-medium">{currentConfig.chainLabel}</label>
                <button
                  type="button"
                  onClick={() => setIsCustomChain(!isCustomChain)}
                  className="text-[10px] text-cyan-400 hover:underline"
                >
                  {isCustomChain ? 'Padrão' : 'Customizada'}
                </button>
              </div>

              {isCustomChain ? (
                <input
                  type="text"
                  value={chain}
                  onChange={(e) => setChain(e.target.value)}
                  placeholder="Nome customizado..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                />
              ) : (
                <select
                  value={chain}
                  onChange={(e) => setChain(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none font-semibold"
                >
                  {availableChains.map((ch: string) => (
                    <option key={ch} value={ch}>{ch}</option>
                  ))}
                </select>
              )}
            </div>

            {/* Action */}
            <div>
              <label className="text-slate-400 block mb-1 font-medium">Ação (Action / Target)</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none font-semibold"
              >
                {currentConfig.actions.map((act: any) => (
                  <option key={act.value} value={act.value}>{act.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Conditional Target Chain or NAT addresses */}
          {action === 'jump' && (
            <div className="p-3 bg-indigo-950/30 rounded-xl border border-indigo-800/40">
              <label className="text-indigo-300 block mb-1 font-medium">Target Chain (Nome da cadeia de salto)</label>
              <input
                type="text"
                value={targetChain}
                onChange={(e) => setTargetChain(e.target.value)}
                placeholder="Ex: scan-protection"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-indigo-500 focus:outline-none"
              />
            </div>
          )}

          {['dst-nat', 'src-nat', 'redirect'].includes(action) && (
            <div className="grid grid-cols-2 gap-3 p-3 bg-amber-950/30 rounded-xl border border-amber-800/40">
              <div>
                <label className="text-amber-300 block mb-1 font-medium">To Addresses (Novo IP)</label>
                <input
                  type="text"
                  value={natAddresses}
                  onChange={(e) => setNatAddresses(e.target.value)}
                  placeholder="Ex: 192.168.1.50"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-amber-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-amber-300 block mb-1 font-medium">To Ports (Nova Porta)</label>
                <input
                  type="text"
                  value={natPorts}
                  onChange={(e) => setNatPorts(e.target.value)}
                  placeholder="Ex: 80"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-amber-500 focus:outline-none"
                />
              </div>
            </div>
          )}

          {/* Matchers: IP, Ports, Lists (adapted labels) */}
          <div className="space-y-3 p-3 bg-slate-950/70 rounded-xl border border-slate-800">
            <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
              Critérios de Correspondência (Matchers)
            </span>

            {/* Protocol & Ports */}
            <div className={`grid ${selectedSyntax === 'routeros' ? 'grid-cols-4' : 'grid-cols-3'} gap-3`}>
              <div>
                <label className="text-slate-400 block mb-1">Protocolo</label>
                <input
                  type="text"
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                  placeholder="tcp, udp, icmp, any"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1 flex items-center justify-between">
                  <span>Src Port</span>
                  {!isPortApplicable && <span className="text-[10px] text-amber-400/80">N/A</span>}
                </label>
                <input
                  type="text"
                  disabled={!isPortApplicable}
                  value={isPortApplicable ? srcPort : ''}
                  onChange={(e) => setSrcPort(e.target.value)}
                  placeholder={isPortApplicable ? "Ex: 1024-65535" : "N/A"}
                  className={`w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none transition ${
                    !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950 text-slate-600' : ''
                  }`}
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1 flex items-center justify-between">
                  <span>Dst Port</span>
                  {!isPortApplicable && <span className="text-[10px] text-amber-400/80">N/A</span>}
                </label>
                <input
                  type="text"
                  disabled={!isPortApplicable}
                  value={isPortApplicable ? dstPort : ''}
                  onChange={(e) => setDstPort(e.target.value)}
                  placeholder={isPortApplicable ? "Ex: 80, 443" : "N/A"}
                  className={`w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none transition ${
                    !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950 text-slate-600' : ''
                  }`}
                />
              </div>
              {selectedSyntax === 'routeros' && (
                <div>
                  <label className="text-slate-400 block mb-1 flex items-center justify-between" title="MikroTik port= (compara tanto porta de origem quanto de destino)">
                    <span>Port (Src ou Dst)</span>
                    {!isPortApplicable && <span className="text-[10px] text-amber-400/80">N/A</span>}
                  </label>
                  <input
                    type="text"
                    disabled={!isPortApplicable}
                    value={isPortApplicable ? anyPort : ''}
                    onChange={(e) => setAnyPort(e.target.value)}
                    placeholder={isPortApplicable ? "Ex: 13231" : "N/A"}
                    title="MikroTik port= (compara tanto porta de origem quanto de destino)"
                    className={`w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none transition ${
                      !isPortApplicable ? 'opacity-40 cursor-not-allowed bg-slate-950 text-slate-600' : ''
                    }`}
                  />
                </div>
              )}
            </div>

            {/* Addresses & Lists (Dynamic Label) */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Src Address (IP ou CIDR)</label>
                <input
                  type="text"
                  value={srcAddress}
                  onChange={(e) => setSrcAddress(e.target.value)}
                  placeholder="Ex: 192.168.1.0/24"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Origem: {currentConfig.listLabel}</label>
                <select
                  value={srcList}
                  onChange={(e) => setSrcList(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none cursor-pointer"
                >
                  <option value="">(Nenhuma)</option>
                  {Object.keys(addressLists).map(name => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Dst Address (IP ou CIDR)</label>
                <input
                  type="text"
                  value={dstAddress}
                  onChange={(e) => setDstAddress(e.target.value)}
                  placeholder="Ex: 10.0.0.1"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Destino: {currentConfig.listLabel}</label>
                <select
                  value={dstList}
                  onChange={(e) => setDstList(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none cursor-pointer"
                >
                  <option value="">(Nenhuma)</option>
                  {Object.keys(addressLists).map(name => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Interfaces */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">In-Interface (Entrada)</label>
                <input
                  type="text"
                  value={inIface}
                  onChange={(e) => setInIface(e.target.value)}
                  placeholder={selectedSyntax === 'cisco' ? 'Ex: GigabitEthernet0/0' : selectedSyntax === 'junos' ? 'Ex: ge-0/0/0' : 'Ex: ether1-wan, eth0'}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Out-Interface (Saída)</label>
                <input
                  type="text"
                  value={outIface}
                  onChange={(e) => setOutIface(e.target.value)}
                  placeholder={selectedSyntax === 'cisco' ? 'Ex: GigabitEthernet0/1' : selectedSyntax === 'junos' ? 'Ex: ge-0/0/1' : 'Ex: ether2-lan, eth1'}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Conntrack States */}
            <div>
              <label className="text-slate-400 block mb-1.5">Connection State / Estado</label>
              <div className="flex flex-wrap gap-2">
                {['new', 'established', 'related', 'invalid', 'untracked'].map((st) => {
                  const active = connStates.includes(st);
                  return (
                    <button
                      key={st}
                      type="button"
                      onClick={() => handleToggleState(st)}
                      className={`px-2.5 py-1 rounded text-xs font-mono transition ${
                        active
                          ? 'bg-teal-950 text-teal-300 border border-teal-700 font-semibold'
                          : 'bg-slate-900 text-slate-400 border border-slate-700 hover:text-white'
                      }`}
                    >
                      {st}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Comment / Term Name / Remark */}
          <div>
            <label className="text-slate-400 block mb-1 font-medium">{currentConfig.commentLabel}</label>
            <input
              type="text"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder={selectedSyntax === 'junos' ? 'Ex: allow-ssh-admin' : selectedSyntax === 'cisco' ? 'Ex: Permit Web and SSH' : 'Ex: Allow LAN to WAN'}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-white bg-slate-800 transition"
          >
            Cancelar
          </button>
          <button
            onClick={handleSave}
            className="px-5 py-2 rounded-lg text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 flex items-center gap-1.5 shadow-lg shadow-cyan-950/50 transition"
          >
            <Save className="w-4 h-4" />
            <span>Salvar Regra</span>
          </button>
        </div>
      </div>
    </div>
  );
};
