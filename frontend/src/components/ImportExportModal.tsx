import React, { useState } from 'react';
import { Upload, Download, Copy, Check, FileText, X, AlertCircle } from 'lucide-react';
import { FirewallRule, AddressList } from '../types';
import { importRulesApi, exportRulesApi } from '../api/client';

interface ImportExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  defaultTab?: 'import' | 'export';
  rules: FirewallRule[];
  addressLists: Record<string, AddressList>;
  onImportSuccess: (importedRules: FirewallRule[], importedLists: Record<string, AddressList>, syntax: string) => void;
}

export const ImportExportModal: React.FC<ImportExportModalProps> = ({
  isOpen,
  onClose,
  defaultTab = 'import',
  rules,
  addressLists,
  onImportSuccess
}) => {
  const [activeTab, setActiveTab] = useState<'import' | 'export'>(defaultTab);
  const [importSyntax, setImportSyntax] = useState<string>('auto');
  const [importContent, setImportContent] = useState<string>('');
  const [exportSyntax, setExportSyntax] = useState<string>('routeros');
  const [exportedContent, setExportedContent] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleImport = async () => {
    if (!importContent.trim()) {
      setErrorMsg('Por favor, cole ou digite as regras antes de importar.');
      return;
    }
    setErrorMsg(null);
    setLoading(true);
    try {
      const res = await importRulesApi(importContent, importSyntax);
      onImportSuccess(res.rules, res.address_lists, res.detected_syntax);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Erro ao importar regras.');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (targetSyntax: string) => {
    setExportSyntax(targetSyntax);
    setErrorMsg(null);
    setLoading(true);
    try {
      const res = await exportRulesApi(targetSyntax, rules, addressLists);
      setExportedContent(res.content);
    } catch (err: any) {
      setErrorMsg(err.message || 'Erro ao exportar regras.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(exportedContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const extensions: Record<string, string> = {
      routeros: 'rsc',
      iptables: 'sh',
      nftables: 'nft',
      cisco: 'txt',
      junos: 'conf'
    };
    const ext = extensions[exportSyntax] || 'txt';
    const blob = new Blob([exportedContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `firewall_rules.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setImportContent(text);
    };
    reader.readAsText(file);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header with Tabs */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
              <button
                onClick={() => { setActiveTab('import'); setErrorMsg(null); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition ${
                  activeTab === 'import'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Importar Regras</span>
              </button>
              <button
                onClick={() => {
                  setActiveTab('export');
                  setErrorMsg(null);
                  if (!exportedContent) handleExport(exportSyntax);
                }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition ${
                  activeTab === 'export'
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Download className="w-3.5 h-3.5" />
                <span>Exportar / Converter</span>
              </button>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 flex-1 overflow-y-auto">
          {errorMsg && (
            <div className="mb-4 p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {activeTab === 'import' ? (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 font-medium">Sintaxe de Entrada:</span>
                  <select
                    value={importSyntax}
                    onChange={(e) => setImportSyntax(e.target.value)}
                    className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-medium cursor-pointer"
                  >
                    <option value="auto">Detecção Automática</option>
                    <option value="routeros">MikroTik RouterOS (v6 / v7)</option>
                    <option value="iptables">Linux iptables & ipset</option>
                    <option value="nftables">nftables</option>
                    <option value="cisco">Cisco ACL / ASA</option>
                    <option value="junos">Juniper Junos OS</option>
                  </select>
                </div>

                <div>
                  <label className="cursor-pointer text-xs font-medium text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 border border-slate-700 transition">
                    <FileText className="w-3.5 h-3.5" />
                    <span>Carregar Arquivo (.rsc, .sh, .nft, .txt)</span>
                    <input
                      type="file"
                      onChange={handleFileUpload}
                      accept=".rsc,.sh,.txt,.nft"
                      className="hidden"
                    />
                  </label>
                </div>
              </div>

              <div>
                <textarea
                  value={importContent}
                  onChange={(e) => setImportContent(e.target.value)}
                  placeholder={`Cole aqui suas regras de firewall no formato do seu roteador ou sistema operacional.\nExemplo MikroTik:\n/ip firewall filter add chain=forward action=accept connection-state=established,related\n/ip firewall address-list add list=BOGONS address=10.0.0.0/8\n\nExemplo iptables:\niptables -A FORWARD -p tcp --dport 80 -j ACCEPT\n\nExemplo Cisco:\nip access-list extended WAN_IN\n permit tcp any host 10.0.0.1 eq 443`}
                  className="w-full h-80 bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none resize-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition"
                >
                  Cancelar
                </button>
                <button
                  onClick={handleImport}
                  disabled={loading}
                  className="px-5 py-2 rounded-lg text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 shadow-md shadow-cyan-950/50 transition disabled:opacity-50 flex items-center gap-1.5"
                >
                  <Upload className="w-4 h-4" />
                  <span>{loading ? 'Processando...' : 'Importar Regras'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 font-medium">Exportar / Converter para:</span>
                  <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
                    {[
                      { id: 'routeros', label: 'MikroTik RouterOS' },
                      { id: 'iptables', label: 'iptables & ipset' },
                      { id: 'nftables', label: 'nftables' },
                      { id: 'cisco', label: 'Cisco ACL' },
                      { id: 'junos', label: 'Juniper Junos' }
                    ].map((item) => (
                      <button
                        key={item.id}
                        onClick={() => handleExport(item.id)}
                        className={`px-2.5 py-1 rounded text-xs transition font-medium ${
                          exportSyntax === item.id
                            ? 'bg-emerald-600 text-white'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition text-xs font-medium"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copiado!' : 'Copiar'}</span>
                  </button>
                  <button
                    onClick={handleDownload}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow transition text-xs font-medium"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Baixar Arquivo</span>
                  </button>
                </div>
              </div>

              <div>
                <textarea
                  readOnly
                  value={exportedContent || 'Gerando regras...'}
                  className="w-full h-80 bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none resize-none"
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
