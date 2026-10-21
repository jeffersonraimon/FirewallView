import React from 'react';
import { Shield, Download, Upload, Plus, Database, Sparkles, RefreshCw } from 'lucide-react';

interface NavbarProps {
  onOpenImport: () => void;
  onOpenExport: () => void;
  onOpenAddressLists: () => void;
  onOpenAddRule: () => void;
  onLoadPreset: (name: string) => void;
  rulesCount: number;
  addressListsCount: number;
  currentSyntax: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenImport,
  onOpenExport,
  onOpenAddressLists,
  onOpenAddRule,
  onLoadPreset,
  rulesCount,
  addressListsCount,
  currentSyntax
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40 px-4 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-emerald-400 p-[1.5px] shadow-lg shadow-cyan-950/40">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg text-white tracking-tight">Firewall<span className="text-cyan-400">View</span></h1>
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono font-medium">
                v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400">Simulador de Fluxo & Validador Multi-Sintaxe</p>
          </div>
        </div>

        {/* Presets Selector */}
        <div className="flex items-center gap-1.5 bg-slate-950/80 p-1 rounded-xl border border-slate-800/80 text-xs">
          <span className="text-slate-400 px-2 flex items-center gap-1 font-medium">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Presets:
          </span>
          <button
            onClick={() => onLoadPreset('routeros')}
            className={`px-2.5 py-1.5 rounded-lg transition-all font-medium ${
              currentSyntax === 'routeros'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            MikroTik RouterOS
          </button>
          <button
            onClick={() => onLoadPreset('iptables')}
            className={`px-2.5 py-1.5 rounded-lg transition-all font-medium ${
              currentSyntax === 'iptables'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            Linux iptables
          </button>
          <button
            onClick={() => onLoadPreset('cisco')}
            className={`px-2.5 py-1.5 rounded-lg transition-all font-medium ${
              currentSyntax === 'cisco'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            Cisco ACL
          </button>
          <button
            onClick={() => onLoadPreset('junos')}
            className={`px-2.5 py-1.5 rounded-lg transition-all font-medium ${
              currentSyntax === 'junos'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            Juniper Junos
          </button>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenAddressLists}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            title="Gerenciar Address Lists / IPsets"
          >
            <Database className="w-3.5 h-3.5 text-violet-400" />
            <span>Address Lists</span>
            <span className="px-1.5 py-0.2 rounded-full bg-violet-950 border border-violet-800 text-[10px] text-violet-300">
              {addressListsCount}
            </span>
          </button>

          <button
            onClick={onOpenImport}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Importar</span>
          </button>

          <button
            onClick={onOpenExport}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>Exportar</span>
          </button>

          <button
            onClick={onOpenAddRule}
            className="flex items-center gap-1.5 text-xs font-medium px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-900/30 transition"
          >
            <Plus className="w-4 h-4" />
            <span>Nova Regra</span>
          </button>
        </div>
      </div>
    </header>
  );
};
