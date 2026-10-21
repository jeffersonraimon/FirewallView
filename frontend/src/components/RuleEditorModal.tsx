import React, { useState, useEffect } from 'react';
import { X, Save, Plus, Shield } from 'lucide-react';
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
  const [table, setTable] = useState('filter');
  const [chain, setChain] = useState('forward');
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
  const [inIface, setInIface] = useState('');
  const [outIface, setOutIface] = useState('');
  const [connStates, setConnStates] = useState<string[]>([]);

  useEffect(() => {
    if (ruleToEdit) {
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
      setInIface(ruleToEdit.conditions.in_interface || '');
      setOutIface(ruleToEdit.conditions.out_interface || '');
      setConnStates(ruleToEdit.conditions.connection_state || []);
    } else {
      setTable('filter');
      let defaultChain = 'forward';
      if (currentSyntax === 'iptables') defaultChain = 'FORWARD';
      else if (currentSyntax === 'cisco') defaultChain = 'WAN_IN';
      else if (currentSyntax === 'junos') defaultChain = 'FILTER_INBOUND';
      setChain(defaultChain);
      setAction('accept');
      setTargetChain('');
      setNatAddresses('');
      setNatPorts('');
      setComment('');
      setProtocol('');
      setSrcAddress('');
      setDstAddress('');
      setSrcList('');
      setDstList('');
      setSrcPort('');
      setDstPort('');
      setInIface('');
      setOutIface('');
      setConnStates([]);
    }
  }, [ruleToEdit, isOpen, currentSyntax]);

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
        src_port: srcPort.trim() || undefined,
        dst_port: dstPort.trim() || undefined,
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
            <h2 className="text-base font-bold text-white">
              {ruleToEdit ? 'Editar Regra de Firewall' : 'Adicionar Nova Regra'}
            </h2>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <div className="p-5 flex-1 overflow-y-auto space-y-4 text-xs font-sans">
          {/* Section 1: Table, Chain, Action */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 bg-slate-950/70 rounded-xl border border-slate-800">
            <div>
              <label className="text-slate-400 block mb-1 font-medium">Tabela</label>
              <select
                value={table}
                onChange={(e) => setTable(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              >
                <option value="filter">filter</option>
                <option value="nat">nat</option>
                <option value="mangle">mangle</option>
                <option value="raw">raw</option>
              </select>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-medium">Chain</label>
              <input
                type="text"
                value={chain}
                onChange={(e) => setChain(e.target.value)}
                placeholder="forward, input, etc."
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-medium">Ação (Action)</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none font-semibold"
              >
                <option value="accept">accept</option>
                <option value="drop">drop</option>
                <option value="reject">reject</option>
                <option value="fasttrack-connection">fasttrack-connection</option>
                <option value="dst-nat">dst-nat</option>
                <option value="src-nat">src-nat</option>
                <option value="masquerade">masquerade</option>
                <option value="redirect">redirect</option>
                <option value="jump">jump</option>
                <option value="return">return</option>
                <option value="log">log</option>
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
                placeholder="Ex: custom-chain-scan"
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

          {/* Matchers: IP, Ports, Lists */}
          <div className="space-y-3 p-3 bg-slate-950/70 rounded-xl border border-slate-800">
            <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
              Critérios de Correspondência (Matchers)
            </span>

            {/* Protocol */}
            <div className="grid grid-cols-3 gap-3">
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
                <label className="text-slate-400 block mb-1">Src Port</label>
                <input
                  type="text"
                  value={srcPort}
                  onChange={(e) => setSrcPort(e.target.value)}
                  placeholder="Ex: 1024-65535"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Dst Port</label>
                <input
                  type="text"
                  value={dstPort}
                  onChange={(e) => setDstPort(e.target.value)}
                  placeholder="Ex: 80, 443"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Addresses & Lists */}
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
                <label className="text-slate-400 block mb-1">Src Address List</label>
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
                <label className="text-slate-400 block mb-1">Dst Address List</label>
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
                <label className="text-slate-400 block mb-1">In-Interface</label>
                <input
                  type="text"
                  value={inIface}
                  onChange={(e) => setInIface(e.target.value)}
                  placeholder="Ex: ether1-wan, eth0"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Out-Interface</label>
                <input
                  type="text"
                  value={outIface}
                  onChange={(e) => setOutIface(e.target.value)}
                  placeholder="Ex: ether2-lan, eth1"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Conntrack States */}
            <div>
              <label className="text-slate-400 block mb-1.5">Connection State</label>
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

          {/* Comment */}
          <div>
            <label className="text-slate-400 block mb-1 font-medium">Comentário / Descrição</label>
            <input
              type="text"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Ex: Allow Web and SSL from Office"
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
