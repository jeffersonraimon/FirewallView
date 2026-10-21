import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { PacketSimulatorPanel } from './components/PacketSimulatorPanel';
import { PacketFlowVisualizer } from './components/PacketFlowVisualizer';
import { RulesTable } from './components/RulesTable';
import { AddressListManager } from './components/AddressListManager';
import { ImportExportModal } from './components/ImportExportModal';
import { RuleEditorModal } from './components/RuleEditorModal';
import { FirewallRule, AddressList, SimulationPacket, SimulationResult } from './types';
import { fetchPreset, runSimulation } from './api/client';

const STORAGE_KEY_SYNTAX = 'firewallview_current_syntax';
const STORAGE_KEY_RULES = 'firewallview_rules';
const STORAGE_KEY_LISTS = 'firewallview_address_lists';
const STORAGE_KEY_PACKET = 'firewallview_packet';

const DEFAULT_PACKET: SimulationPacket = {
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
};

const BLANK_PACKET: SimulationPacket = {
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
};

export function App() {
  const [currentSyntax, setCurrentSyntax] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEY_SYNTAX) || 'routeros';
  });

  const [rules, setRules] = useState<FirewallRule[]>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_RULES);
    if (saved !== null) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Error parsing stored rules', e);
      }
    }
    return [];
  });

  const [addressLists, setAddressLists] = useState<Record<string, AddressList>>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_LISTS);
    if (saved !== null) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Error parsing stored address lists', e);
      }
    }
    return {};
  });

  const [packet, setPacket] = useState<SimulationPacket>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_PACKET);
    if (saved !== null) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Error parsing stored packet', e);
      }
    }
    return DEFAULT_PACKET;
  });

  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [selectedStage, setSelectedStage] = useState<string | null>(null);
  const [autoSimulate, setAutoSimulate] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);

  // Modals state
  const [isImportExportOpen, setIsImportExportOpen] = useState<boolean>(false);
  const [importExportTab, setImportExportTab] = useState<'import' | 'export'>('import');
  const [isAddressListOpen, setIsAddressListOpen] = useState<boolean>(false);
  const [isRuleEditorOpen, setIsRuleEditorOpen] = useState<boolean>(false);
  const [ruleToEdit, setRuleToEdit] = useState<FirewallRule | null>(null);

  const debounceTimerRef = useRef<number | null>(null);
  const isFirstMount = useRef<boolean>(true);

  // Sync state changes to localStorage
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_SYNTAX, currentSyntax);
  }, [currentSyntax]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_RULES, JSON.stringify(rules));
  }, [rules]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_LISTS, JSON.stringify(addressLists));
  }, [addressLists]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_PACKET, JSON.stringify(packet));
  }, [packet]);

  // Initial load: either run existing state from localStorage, or load preset if first time ever
  useEffect(() => {
    if (isFirstMount.current) {
      isFirstMount.current = false;
      const hasStoredData = localStorage.getItem(STORAGE_KEY_RULES) !== null;

      if (hasStoredData) {
        // Restore and simulate immediately with user's saved state
        executeSimulation(packet, rules, addressLists);
      } else {
        // First visit ever: load default routeros preset
        loadPresetData('routeros');
      }
    }
  }, []);

  const handleClearToBlank = () => {
    setRules([]);
    setAddressLists({});
    setPacket(BLANK_PACKET);
    setSelectedStage(null);
    executeSimulation(BLANK_PACKET, [], {});
  };

  const loadPresetData = async (presetName: string) => {
    setLoading(true);
    try {
      const data = await fetchPreset(presetName);
      setRules(data.rules);
      setAddressLists(data.address_lists);
      setCurrentSyntax(presetName);

      // If packet was cleared (blank), reset it to DEFAULT_PACKET when loading an example preset
      const targetPacket = (!packet.src_ip && !packet.dst_ip) ? DEFAULT_PACKET : packet;
      if (!packet.src_ip && !packet.dst_ip) {
        setPacket(DEFAULT_PACKET);
      }

      // Trigger simulation
      const res = await runSimulation(targetPacket, data.rules, data.address_lists);
      setSimulationResult(res);
    } catch (err) {
      console.error('Failed to load preset', err);
    } finally {
      setLoading(false);
    }
  };

  const executeSimulation = async (
    targetPacket = packet,
    targetRules = rules,
    targetLists = addressLists
  ) => {
    setLoading(true);
    try {
      const res = await runSimulation(targetPacket, targetRules, targetLists);
      setSimulationResult(res);
    } catch (err) {
      console.error('Simulation error', err);
    } finally {
      setLoading(false);
    }
  };

  // Handle packet changes with debounce if autoSimulate is true
  const handlePacketChange = (newPacket: SimulationPacket) => {
    setPacket(newPacket);
    if (autoSimulate) {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = window.setTimeout(() => {
        executeSimulation(newPacket, rules, addressLists);
      }, 250);
    }
  };

  // Rule operations
  const handleToggleRule = (ruleId: string) => {
    const updated = rules.map((r) =>
      r.id === ruleId ? { ...r, disabled: !r.disabled } : r
    );
    setRules(updated);
    if (autoSimulate) executeSimulation(packet, updated, addressLists);
  };

  const handleMoveRule = (ruleId: string, direction: 'up' | 'down') => {
    const index = rules.findIndex((r) => r.id === ruleId);
    if (index < 0) return;
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= rules.length) return;

    const newRules = [...rules];
    const temp = newRules[index];
    newRules[index] = newRules[targetIndex];
    newRules[targetIndex] = temp;

    // Recalculate order numbers
    const reordered = newRules.map((r, i) => ({ ...r, order: i + 1 }));
    setRules(reordered);
    if (autoSimulate) executeSimulation(packet, reordered, addressLists);
  };

  const handleDeleteRule = (ruleId: string) => {
    const filtered = rules.filter((r) => r.id !== ruleId);
    const reordered = filtered.map((r, i) => ({ ...r, order: i + 1 }));
    setRules(reordered);
    if (autoSimulate) executeSimulation(packet, reordered, addressLists);
  };

  const handleSaveRule = (savedRule: FirewallRule) => {
    let updatedRules: FirewallRule[];
    const exists = rules.some((r) => r.id === savedRule.id);
    if (exists) {
      updatedRules = rules.map((r) => (r.id === savedRule.id ? savedRule : r));
    } else {
      updatedRules = [...rules, { ...savedRule, order: rules.length + 1 }];
    }
    setRules(updatedRules);
    if (autoSimulate) executeSimulation(packet, updatedRules, addressLists);
  };

  const handleUpdateAddressLists = (newLists: Record<string, AddressList>) => {
    setAddressLists(newLists);
    if (autoSimulate) executeSimulation(packet, rules, newLists);
  };

  const handleImportSuccess = (
    importedRules: FirewallRule[],
    importedLists: Record<string, AddressList>,
    detectedSyntax: string
  ) => {
    setRules(importedRules);
    setAddressLists(importedLists);
    setCurrentSyntax(detectedSyntax);

    const targetPacket = (!packet.src_ip && !packet.dst_ip) ? DEFAULT_PACKET : packet;
    if (!packet.src_ip && !packet.dst_ip) {
      setPacket(DEFAULT_PACKET);
    }
    executeSimulation(targetPacket, importedRules, importedLists);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar
        onOpenImport={() => {
          setImportExportTab('import');
          setIsImportExportOpen(true);
        }}
        onOpenExport={() => {
          setImportExportTab('export');
          setIsImportExportOpen(true);
        }}
        onOpenAddressLists={() => setIsAddressListOpen(true)}
        onOpenAddRule={() => {
          setRuleToEdit(null);
          setIsRuleEditorOpen(true);
        }}
        onClearRules={handleClearToBlank}
        onLoadPreset={loadPresetData}
        onChangeSyntax={(syntax) => {
          setCurrentSyntax(syntax);
        }}
        rulesCount={rules.length}
        addressListsCount={Object.keys(addressLists).length}
        currentSyntax={currentSyntax}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6">
        {/* Packet Injector & Simulator Panel */}
        <PacketSimulatorPanel
          packet={packet}
          onChangePacket={handlePacketChange}
          onSimulate={() => executeSimulation()}
          autoSimulate={autoSimulate}
          onToggleAutoSimulate={() => setAutoSimulate(!autoSimulate)}
          loading={loading}
        />

        {/* Visualizer of Decision Pipeline */}
        <PacketFlowVisualizer
          simulationResult={simulationResult}
          selectedStage={selectedStage}
          onSelectStage={setSelectedStage}
        />

        {/* Rules Table */}
        <RulesTable
          rules={rules}
          simulationResult={simulationResult}
          selectedStage={selectedStage}
          onToggleRule={handleToggleRule}
          onMoveRule={handleMoveRule}
          onDeleteRule={handleDeleteRule}
          onEditRule={(rule) => {
            setRuleToEdit(rule);
            setIsRuleEditorOpen(true);
          }}
          onOpenAddRule={() => {
            setRuleToEdit(null);
            setIsRuleEditorOpen(true);
          }}
          currentSyntax={currentSyntax}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 px-6 text-center text-xs text-slate-500">
        <p>FirewallView &bull; Simulador de Políticas de Segurança de Rede Multi-Plataforma &bull; MikroTik RouterOS, Linux iptables/nftables, Cisco ACL, Juniper Junos</p>
      </footer>

      {/* Modals */}
      <AddressListManager
        isOpen={isAddressListOpen}
        onClose={() => setIsAddressListOpen(false)}
        addressLists={addressLists}
        onUpdateAddressLists={handleUpdateAddressLists}
      />

      <ImportExportModal
        isOpen={isImportExportOpen}
        onClose={() => setIsImportExportOpen(false)}
        defaultTab={importExportTab}
        rules={rules}
        addressLists={addressLists}
        onImportSuccess={handleImportSuccess}
      />

      <RuleEditorModal
        isOpen={isRuleEditorOpen}
        onClose={() => setIsRuleEditorOpen(false)}
        ruleToEdit={ruleToEdit}
        onSaveRule={handleSaveRule}
        addressLists={addressLists}
        currentSyntax={currentSyntax}
      />
    </div>
  );
}

export default App;
