import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  Download,
  Upload,
  Plus,
  Database,
  Sparkles,
  RotateCcw,
  ChevronDown,
  FileCode,
  Layers
} from 'lucide-react';

interface NavbarProps {
  onOpenImport: () => void;
  onOpenExport: () => void;
  onOpenAddressLists: () => void;
  onOpenAddRule: () => void;
  onClearRules: () => void;
  onLoadPreset: (name: string) => void;
  onChangeSyntax: (syntax: string) => void;
  rulesCount: number;
  addressListsCount: number;
  currentSyntax: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenImport,
  onOpenExport,
  onOpenAddressLists,
  onOpenAddRule,
  onClearRules,
  onLoadPreset,
  onChangeSyntax,
  rulesCount,
  addressListsCount,
  currentSyntax
}) => {
  const [isPresetsOpen, setIsPresetsOpen] = useState(false);
  const presetsRef = useRef<HTMLDivElement>(null);

  // Close presets dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (presetsRef.current && !presetsRef.current.contains(event.target as Node)) {
        setIsPresetsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const platforms = [
    { id: 'routeros', name: 'MikroTik RouterOS', icon: '⚡' },
    { id: 'iptables', name: 'Linux iptables & ipset', icon: '🐧' },
    { id: 'nftables', name: 'Linux nftables', icon: '🛡️' },
    { id: 'cisco', name: 'Cisco IOS / ASA', icon: '🏢' },
    { id: 'junos', name: 'Juniper Junos OS', icon: '🌲' },
  ];

  const presets = [
    { id: 'routeros', title: 'MikroTik Default & Bogons', desc: 'Regras de borda, LAN->WAN e Address Lists' },
    { id: 'iptables', title: 'Linux iptables Web & DMZ', desc: 'Filtro INPUT/FORWARD e conjuntos ipset' },
    { id: 'cisco', title: 'Cisco Edge Enterprise ACL', desc: 'Extended ACL com object-groups de rede' },
    { id: 'junos', title: 'Juniper Junos Edge Filter', desc: 'Filter inet com prefix-list e termos' },
  ];

  return (
    <header className="border-b border-slate-800/80 bg-slate-900/95 backdrop-blur sticky top-0 z-40 px-4 py-2.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Left: Brand + Equipment Selector */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-emerald-400 p-[1.5px] shadow-sm shadow-cyan-950">
              <div className="w-full h-full bg-slate-950 rounded-[9px] flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan-400" />
              </div>
            </div>
            <div>
              <h1 className="font-bold text-sm text-white tracking-tight leading-none">
                Firewall<span className="text-cyan-400">View</span>
              </h1>
            </div>
          </div>

          <div className="h-4 w-[1px] bg-slate-800 mx-1 hidden sm:block" />

          {/* Integrated Equipment Selector */}
          <div className="relative">
            <select
              value={currentSyntax}
              onChange={(e) => onChangeSyntax(e.target.value)}
              className="bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 font-medium cursor-pointer focus:border-cyan-500 focus:outline-none transition appearance-none pr-7"
            >
              {platforms.map((p) => (
                <option key={p.id} value={p.id} className="bg-slate-900 text-slate-200 py-1">
                  {p.icon} {p.name}
                </option>
              ))}
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-slate-500 absolute right-2 top-2.5 pointer-events-none" />
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2">
          {/* Clear / Do Zero */}
          <button
            onClick={onClearRules}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent hover:border-slate-800 transition"
            title="Limpar todas as regras e começar do zero neste equipamento"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Limpar / Do Zero</span>
          </button>

          {/* Dropdown de Exemplos / Presets */}
          <div className="relative" ref={presetsRef}>
            <button
              onClick={() => setIsPresetsOpen(!isPresetsOpen)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-950 hover:bg-slate-800/80 border border-slate-800 transition"
            >
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              <span>Exemplos</span>
              <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${isPresetsOpen ? 'rotate-180' : ''}`} />
            </button>

            {isPresetsOpen && (
              <div className="absolute right-0 mt-1.5 w-64 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl py-1.5 z-50 text-xs">
                <div className="px-3 py-1.5 text-[10px] uppercase font-mono tracking-wider text-slate-500 border-b border-slate-800/60">
                  Carregar Modelo de Regras
                </div>
                {presets.map((preset) => (
                  <button
                    key={preset.id}
                    onClick={() => {
                      onLoadPreset(preset.id);
                      setIsPresetsOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 hover:bg-slate-800/80 transition flex flex-col gap-0.5"
                  >
                    <span className="font-semibold text-slate-200">{preset.title}</span>
                    <span className="text-[11px] text-slate-400">{preset.desc}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="h-4 w-[1px] bg-slate-800 mx-0.5 hidden sm:block" />

          {/* Address Lists */}
          <button
            onClick={onOpenAddressLists}
            className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition border border-transparent hover:border-slate-800"
            title="Gerenciar Address Lists / IPsets"
          >
            <Database className="w-3.5 h-3.5 text-violet-400" />
            <span className="hidden sm:inline">Address Lists</span>
            {addressListsCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-violet-950 border border-violet-800 text-[10px] text-violet-300 font-mono">
                {addressListsCount}
              </span>
            )}
          </button>

          {/* Import */}
          <button
            onClick={onOpenImport}
            className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition border border-transparent hover:border-slate-800"
            title="Importar regras"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Importar</span>
          </button>

          {/* Export */}
          <button
            onClick={onOpenExport}
            className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition border border-transparent hover:border-slate-800"
            title="Exportar ou converter regras"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Exportar</span>
          </button>

          {/* Primary Action: New Rule */}
          <button
            onClick={onOpenAddRule}
            className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-950/40 transition"
          >
            <Plus className="w-4 h-4" />
            <span>Nova Regra</span>
          </button>
        </div>
      </div>
    </header>
  );
};
