import React, { useState } from 'react';
import { Database, Plus, Trash2, X, Search, Check, AlertCircle } from 'lucide-react';
import { AddressList, AddressListEntry } from '../types';

interface AddressListManagerProps {
  isOpen: boolean;
  onClose: () => void;
  addressLists: Record<string, AddressList>;
  onUpdateAddressLists: (newLists: Record<string, AddressList>) => void;
}

export const AddressListManager: React.FC<AddressListManagerProps> = ({
  isOpen,
  onClose,
  addressLists,
  onUpdateAddressLists
}) => {
  const [selectedList, setSelectedList] = useState<string>(
    Object.keys(addressLists)[0] || ''
  );
  const [newListName, setNewListName] = useState('');
  const [newEntryAddress, setNewEntryAddress] = useState('');
  const [newEntryComment, setNewEntryComment] = useState('');
  const [testIp, setTestIp] = useState('');
  const [testResult, setTestResult] = useState<string | null>(null);

  if (!isOpen) return null;

  const currentList = addressLists[selectedList];

  const handleCreateList = () => {
    const trimmed = newListName.trim();
    if (!trimmed) return;
    if (addressLists[trimmed]) {
      alert('Uma lista com este nome já existe!');
      return;
    }
    const updated = {
      ...addressLists,
      [trimmed]: {
        name: trimmed,
        entries: []
      }
    };
    onUpdateAddressLists(updated);
    setSelectedList(trimmed);
    setNewListName('');
  };

  const handleAddEntry = () => {
    const addr = newEntryAddress.trim();
    if (!addr || !selectedList) return;

    const newEntry: AddressListEntry = {
      id: Math.random().toString(36).substring(2, 9),
      address: addr,
      comment: newEntryComment.trim() || undefined,
      disabled: false
    };

    const updatedList = {
      ...addressLists[selectedList],
      entries: [...(addressLists[selectedList]?.entries || []), newEntry]
    };

    onUpdateAddressLists({
      ...addressLists,
      [selectedList]: updatedList
    });

    setNewEntryAddress('');
    setNewEntryComment('');
  };

  const handleDeleteEntry = (entryId?: string) => {
    if (!entryId || !selectedList) return;
    const updatedEntries = addressLists[selectedList].entries.filter(e => e.id !== entryId);
    onUpdateAddressLists({
      ...addressLists,
      [selectedList]: {
        ...addressLists[selectedList],
        entries: updatedEntries
      }
    });
  };

  const handleDeleteList = (listName: string) => {
    if (!confirm(`Deseja realmente remover a lista '${listName}'?`)) return;
    const updated = { ...addressLists };
    delete updated[listName];
    onUpdateAddressLists(updated);
    setSelectedList(Object.keys(updated)[0] || '');
  };

  const handleTestIp = () => {
    const ip = testIp.trim();
    if (!ip) {
      setTestResult(null);
      return;
    }

    const matches: string[] = [];
    // Simple client-side IP match check for prefix or exact
    for (const [name, alist] of Object.entries(addressLists)) {
      for (const entry of alist.entries) {
        if (entry.disabled) continue;
        if (entry.address === ip || ip.startsWith(entry.address.split('/')[0].split('.').slice(0, 3).join('.'))) {
          matches.push(`${name} (${entry.address})`);
        }
      }
    }

    if (matches.length > 0) {
      setTestResult(`IP ${ip} coincide com: ${matches.join(', ')}`);
    } else {
      setTestResult(`IP ${ip} não encontrado nas listas ativas.`);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-violet-400" />
            <h2 className="text-base font-bold text-white">
              Gerenciador de Address Lists & IPsets
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-800 overflow-hidden">
          {/* Lists Sidebar */}
          <div className="p-4 flex flex-col justify-between overflow-y-auto">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-2">
                Listas Cadastradas ({Object.keys(addressLists).length})
              </span>
              <div className="space-y-1 mb-4">
                {Object.keys(addressLists).map((name) => {
                  const isSelected = selectedList === name;
                  const count = addressLists[name].entries.length;
                  return (
                    <div
                      key={name}
                      onClick={() => setSelectedList(name)}
                      className={`flex items-center justify-between p-2 rounded-lg cursor-pointer transition text-xs font-mono ${
                        isSelected
                          ? 'bg-violet-950/60 text-violet-200 border border-violet-700/60 font-semibold'
                          : 'text-slate-300 hover:bg-slate-800/60'
                      }`}
                    >
                      <span className="truncate">{name}</span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 text-[10px]">
                        {count}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Create new list form */}
            <div className="pt-3 border-t border-slate-800">
              <label className="text-[11px] text-slate-400 block mb-1">Criar Nova Lista</label>
              <div className="flex gap-1.5">
                <input
                  type="text"
                  value={newListName}
                  onChange={(e) => setNewListName(e.target.value)}
                  placeholder="Ex: BLACKLIST_GEO"
                  className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-xs text-slate-100 font-mono focus:border-violet-500 focus:outline-none"
                />
                <button
                  onClick={handleCreateList}
                  className="p-1.5 bg-violet-600 hover:bg-violet-500 text-white rounded-lg transition"
                  title="Criar Lista"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* List Entries Details */}
          <div className="md:col-span-2 p-4 flex flex-col justify-between overflow-y-auto">
            <div>
              {currentList ? (
                <>
                  <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
                    <div>
                      <h3 className="text-sm font-bold text-white font-mono">{currentList.name}</h3>
                      <p className="text-xs text-slate-400">
                        {currentList.entries.length} entradas de rede/IP cadastradas
                      </p>
                    </div>
                    <button
                      onClick={() => handleDeleteList(currentList.name)}
                      className="text-xs text-rose-400 hover:text-rose-300 px-2 py-1 rounded bg-rose-950/40 border border-rose-800/60 flex items-center gap-1 transition"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Excluir Lista
                    </button>
                  </div>

                  {/* Add Entry Form */}
                  <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 mb-4 text-xs">
                    <span className="text-[11px] font-semibold text-violet-400 uppercase tracking-wider block mb-2">
                      Adicionar IP / CIDR / Range
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2">
                      <input
                        type="text"
                        value={newEntryAddress}
                        onChange={(e) => setNewEntryAddress(e.target.value)}
                        placeholder="Ex: 10.0.0.0/8, 192.168.1.5, 10.1.1.1-10.1.1.50"
                        className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 font-mono text-slate-100 focus:border-violet-500 focus:outline-none"
                      />
                      <input
                        type="text"
                        value={newEntryComment}
                        onChange={(e) => setNewEntryComment(e.target.value)}
                        placeholder="Comentário (opcional)"
                        className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 focus:border-violet-500 focus:outline-none"
                      />
                    </div>
                    <button
                      onClick={handleAddEntry}
                      className="px-3 py-1.5 bg-violet-600 hover:bg-violet-500 text-white rounded-lg font-medium transition flex items-center gap-1.5"
                    >
                      <Plus className="w-3.5 h-3.5" /> Adicionar Entrada
                    </button>
                  </div>

                  {/* Entries Table */}
                  <div className="max-h-56 overflow-y-auto rounded-lg border border-slate-800">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950 text-slate-400 text-[10px] uppercase border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Endereço (IP / Subnet / Range)</th>
                          <th className="py-2 px-3">Comentário</th>
                          <th className="py-2 px-3 text-right">Ação</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {currentList.entries.length === 0 ? (
                          <tr>
                            <td colSpan={3} className="py-4 text-center text-slate-500">
                              Nenhuma entrada cadastrada nesta lista.
                            </td>
                          </tr>
                        ) : (
                          currentList.entries.map((entry) => (
                            <tr key={entry.id} className="hover:bg-slate-800/40">
                              <td className="py-2 px-3 text-violet-300 font-semibold">
                                {entry.address}
                              </td>
                              <td className="py-2 px-3 text-slate-400 italic">
                                {entry.comment || '-'}
                              </td>
                              <td className="py-2 px-3 text-right">
                                <button
                                  onClick={() => handleDeleteEntry(entry.id)}
                                  className="text-slate-500 hover:text-rose-400 p-1 transition"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <div className="py-12 text-center text-slate-500 text-xs">
                  Selecione uma lista ou crie uma nova para começar.
                </div>
              )}
            </div>

            {/* Quick IP Tester */}
            <div className="mt-4 pt-3 border-t border-slate-800 bg-slate-950/40 p-3 rounded-xl border border-slate-800 text-xs">
              <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block mb-1">
                Validador Rápido de IP
              </span>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={testIp}
                  onChange={(e) => setTestIp(e.target.value)}
                  placeholder="Digite um IP para testar (ex: 10.5.5.5)"
                  className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 font-mono text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
                <button
                  onClick={handleTestIp}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition"
                >
                  Checar Pertencimento
                </button>
              </div>
              {testResult && (
                <div className="mt-2 text-slate-300 font-mono text-[11px] bg-slate-900 p-2 rounded border border-slate-800">
                  {testResult}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
