import React, { useState } from 'react';
import {
  Check,
  X,
  ArrowUp,
  ArrowDown,
  Trash2,
  Edit,
  Power,
  Info,
  Filter,
  Layers,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { FirewallRule, SimulationResult, RuleEvaluation } from '../types';

interface RulesTableProps {
  rules: FirewallRule[];
  simulationResult: SimulationResult | null;
  selectedStage: string | null;
  onToggleRule: (ruleId: string) => void;
  onMoveRule: (ruleId: string, direction: 'up' | 'down') => void;
  onDeleteRule: (ruleId: string) => void;
  onEditRule: (rule: FirewallRule) => void;
  onOpenAddRule?: () => void;
  currentSyntax?: string;
}

export const RulesTable: React.FC<RulesTableProps> = ({
  rules,
  simulationResult,
  selectedStage,
  onToggleRule,
  onMoveRule,
  onDeleteRule,
  onEditRule,
  onOpenAddRule,
  currentSyntax = 'routeros'
}) => {
  const [tableFilter, setTableFilter] = useState<string>('all');
  const [chainFilter, setChainFilter] = useState<string>('all');
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  // Map rule evaluations from simulation result for fast lookup
  const evaluationMap = new Map<string, RuleEvaluation>();
  if (simulationResult) {
    for (const stage of simulationResult.stages) {
      for (const evalItem of stage.evaluated_rules) {
        evaluationMap.set(evalItem.rule_id, evalItem);
      }
    }
  }

  // Filter rules
  const filteredRules = rules.filter((r) => {
    if (selectedStage) {
      // Find stage in simulation result to get its table/chain
      const stage = simulationResult?.stages.find(s => s.stage_id === selectedStage);
      if (stage && stage.table !== 'system') {
        if (r.table.toLowerCase() !== stage.table.toLowerCase() || r.chain.toLowerCase() !== stage.chain.toLowerCase()) {
          return false;
        }
      }
    }
    if (tableFilter !== 'all' && r.table.toLowerCase() !== tableFilter.toLowerCase()) {
      return false;
    }
    if (chainFilter !== 'all' && r.chain.toLowerCase() !== chainFilter.toLowerCase()) {
      return false;
    }
    return true;
  });

  const getActionBadgeClass = (action: string) => {
    const act = action.toLowerCase();
    if (act === 'accept' || act === 'fasttrack-connection') {
      return 'bg-emerald-950 text-emerald-300 border-emerald-800';
    }
    if (act === 'drop') {
      return 'bg-rose-950 text-rose-300 border-rose-800';
    }
    if (act === 'reject') {
      return 'bg-orange-950 text-orange-300 border-orange-800';
    }
    if (act === 'dst-nat' || act === 'src-nat' || act === 'masquerade' || act === 'redirect') {
      return 'bg-amber-950 text-amber-300 border-amber-800';
    }
    if (act === 'jump' || act === 'return') {
      return 'bg-indigo-950 text-indigo-300 border-indigo-800';
    }
    return 'bg-slate-800 text-slate-300 border-slate-700';
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden mb-8">
      {/* Table Header & Filters */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-white tracking-wider uppercase">
            Regras de Firewall ({filteredRules.length} de {rules.length})
          </h2>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Tabela:</span>
            <select
              value={tableFilter}
              onChange={(e) => setTableFilter(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="all">Todas as Tabelas</option>
              <option value="filter">Filter</option>
              <option value="nat">NAT</option>
              <option value="mangle">Mangle</option>
              <option value="raw">Raw</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Chain:</span>
            <select
              value={chainFilter}
              onChange={(e) => setChainFilter(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="all">Todas as Chains</option>
              <option value="forward">forward</option>
              <option value="input">input</option>
              <option value="output">output</option>
              <option value="prerouting">prerouting</option>
              <option value="postrouting">postrouting</option>
              <option value="srcnat">srcnat</option>
              <option value="dstnat">dstnat</option>
            </select>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3 w-12 text-center">#</th>
              <th className="py-2.5 px-3 w-28">Status / Match</th>
              <th className="py-2.5 px-3 w-24">Tabela/Chain</th>
              <th className="py-2.5 px-3 w-24">Ação</th>
              <th className="py-2.5 px-4">Condições & Matchers</th>
              <th className="py-2.5 px-3">Comentário</th>
              <th className="py-2.5 px-3 w-28 text-right">Ações</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-sans">
            {filteredRules.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-400">
                  {rules.length === 0 ? (
                    <div className="max-w-md mx-auto space-y-3">
                      <div className="w-12 h-12 rounded-2xl bg-cyan-950/40 border border-cyan-800/40 text-cyan-400 flex items-center justify-center mx-auto">
                        <Layers className="w-6 h-6" />
                      </div>
                      <h4 className="text-sm font-bold text-slate-200">
                        Cenário Manual Vazio ({currentSyntax.toUpperCase()})
                      </h4>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        Nenhuma regra cadastrada ainda. Crie sua primeira regra de firewall para validar o comportamento dos pacotes no fluxo de decisão.
                      </p>
                      {onOpenAddRule && (
                        <button
                          type="button"
                          onClick={onOpenAddRule}
                          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg text-xs shadow-md shadow-cyan-950/50 inline-flex items-center gap-1.5 transition"
                        >
                          <span>+ Adicionar Primeira Regra</span>
                        </button>
                      )}
                    </div>
                  ) : (
                    <span>Nenhuma regra encontrada com os filtros selecionados.</span>
                  )}
                </td>
              </tr>
            ) : (
              filteredRules.map((rule, idx) => {
                const evalInfo = evaluationMap.get(rule.id);
                const isMatched = evalInfo?.matched;
                const wasEvaluated = evalInfo !== undefined;
                const isExpanded = expandedRuleId === rule.id;

                let rowBg = rule.disabled ? 'opacity-40 bg-slate-950/40' : 'hover:bg-slate-800/40';
                if (isMatched) {
                  rowBg = 'bg-cyan-950/20 hover:bg-cyan-950/30 border-l-2 border-l-cyan-400';
                }

                return (
                  <React.Fragment key={rule.id}>
                    <tr className={`transition-colors ${rowBg}`}>
                      {/* Order */}
                      <td className="py-3 px-3 text-center font-mono text-slate-400">
                        {rule.order}
                      </td>

                      {/* Live Match Status */}
                      <td className="py-3 px-3">
                        {rule.disabled ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-500 border border-slate-700">
                            Desativada
                          </span>
                        ) : wasEvaluated ? (
                          isMatched ? (
                            <button
                              onClick={() => setExpandedRuleId(isExpanded ? null : rule.id)}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-700 shadow-sm shadow-emerald-950 hover:bg-emerald-900 transition"
                            >
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span>MATCH</span>
                              {isExpanded ? <ChevronUp className="w-2.5 h-2.5" /> : <ChevronDown className="w-2.5 h-2.5" />}
                            </button>
                          ) : (
                            <button
                              onClick={() => setExpandedRuleId(isExpanded ? null : rule.id)}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400 border border-slate-700 hover:text-slate-200 transition"
                            >
                              <X className="w-3 h-3 text-slate-500" />
                              <span>No Match</span>
                              {isExpanded ? <ChevronUp className="w-2.5 h-2.5" /> : <ChevronDown className="w-2.5 h-2.5" />}
                            </button>
                          )
                        ) : (
                          <span className="text-slate-600 font-mono text-[11px]">-</span>
                        )}
                      </td>

                      {/* Table & Chain */}
                      <td className="py-3 px-3">
                        <span className="font-mono text-slate-300 block font-medium">
                          {rule.chain}
                        </span>
                        <span className="text-[10px] text-slate-500 uppercase font-mono block">
                          {rule.table}
                        </span>
                      </td>

                      {/* Action */}
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded-md border text-[11px] font-mono font-medium ${getActionBadgeClass(rule.action)}`}>
                          {rule.action}
                        </span>
                        {rule.target_chain && (
                          <span className="text-[10px] text-indigo-300 block font-mono mt-0.5">
                            → {rule.target_chain}
                          </span>
                        )}
                        {rule.nat_to_addresses && (
                          <span className="text-[10px] text-amber-300 block font-mono mt-0.5">
                            to: {rule.nat_to_addresses}{rule.nat_to_ports ? `:${rule.nat_to_ports}` : ''}
                          </span>
                        )}
                      </td>

                      {/* Conditions & Matchers */}
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                          {/* Protocol */}
                          {rule.conditions.protocol && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-violet-300">
                              proto:{rule.conditions.negate_protocol ? '!' : ''}{rule.conditions.protocol}
                            </span>
                          )}

                          {/* Source IP / List */}
                          {rule.conditions.src_address && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-300">
                              src:{rule.conditions.negate_src_address ? '!' : ''}{rule.conditions.src_address}
                            </span>
                          )}
                          {rule.conditions.src_address_list && (
                            <span className="px-1.5 py-0.5 rounded bg-violet-950 border border-violet-800 text-violet-300">
                              src-list:{rule.conditions.negate_src_address_list ? '!' : ''}{rule.conditions.src_address_list}
                            </span>
                          )}

                          {/* Destination IP / List */}
                          {rule.conditions.dst_address && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-emerald-300">
                              dst:{rule.conditions.negate_dst_address ? '!' : ''}{rule.conditions.dst_address}
                            </span>
                          )}
                          {rule.conditions.dst_address_list && (
                            <span className="px-1.5 py-0.5 rounded bg-violet-950 border border-violet-800 text-violet-300">
                              dst-list:{rule.conditions.negate_dst_address_list ? '!' : ''}{rule.conditions.dst_address_list}
                            </span>
                          )}

                          {/* Ports */}
                          {rule.conditions.src_port && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                              sport:{rule.conditions.negate_src_port ? '!' : ''}{rule.conditions.src_port}
                            </span>
                          )}
                          {rule.conditions.dst_port && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-amber-300 font-semibold">
                              dport:{rule.conditions.negate_dst_port ? '!' : ''}{rule.conditions.dst_port}
                            </span>
                          )}
                          {rule.conditions.port && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-amber-300 font-semibold">
                              port:{rule.conditions.negate_port ? '!' : ''}{rule.conditions.port}
                            </span>
                          )}

                          {/* Interfaces */}
                          {rule.conditions.in_interface && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-blue-300">
                              in:{rule.conditions.negate_in_interface ? '!' : ''}{rule.conditions.in_interface}
                            </span>
                          )}
                          {rule.conditions.out_interface && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-blue-300">
                              out:{rule.conditions.negate_out_interface ? '!' : ''}{rule.conditions.out_interface}
                            </span>
                          )}

                          {/* Connection State */}
                          {rule.conditions.connection_state && rule.conditions.connection_state.length > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-teal-300">
                              state:{rule.conditions.connection_state.join(',')}
                            </span>
                          )}

                          {/* TCP Flags */}
                          {rule.conditions.tcp_flags && rule.conditions.tcp_flags.length > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-amber-300">
                              tcp-flags:{rule.conditions.tcp_flags.join(',')}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Comment */}
                      <td className="py-3 px-3 text-slate-400 italic max-w-xs truncate">
                        {rule.comment || '-'}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => onToggleRule(rule.id)}
                            className={`p-1.5 rounded transition ${
                              rule.disabled
                                ? 'text-slate-600 hover:text-slate-400'
                                : 'text-emerald-400 hover:bg-emerald-950/40'
                            }`}
                            title={rule.disabled ? 'Ativar Regra' : 'Desativar Regra'}
                          >
                            <Power className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => onMoveRule(rule.id, 'up')}
                            disabled={idx === 0}
                            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-30 transition"
                            title="Mover para cima"
                          >
                            <ArrowUp className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => onMoveRule(rule.id, 'down')}
                            disabled={idx === filteredRules.length - 1}
                            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-30 transition"
                            title="Mover para baixo"
                          >
                            <ArrowDown className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => onEditRule(rule)}
                            className="p-1.5 rounded text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition"
                            title="Editar Regra"
                          >
                            <Edit className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => onDeleteRule(rule.id)}
                            className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition"
                            title="Excluir Regra"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expanded Evaluation Breakdown */}
                    {isExpanded && evalInfo && (
                      <tr className="bg-slate-950/90 border-b border-slate-800 font-mono text-xs">
                        <td colSpan={7} className="p-3 pl-12">
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-2 text-[11px] text-slate-400">
                              <Info className="w-3.5 h-3.5 text-cyan-400" />
                              <span className="font-semibold text-slate-200">
                                Detalhamento da Avaliação desta Regra:
                              </span>
                              {evalInfo.applied_effect && (
                                <span className="text-amber-400 font-medium">
                                  ({evalInfo.applied_effect})
                                </span>
                              )}
                            </div>
                            <ul className="list-disc list-inside space-y-0.5 text-slate-300 text-[11px] pl-2">
                              {evalInfo.reasons.map((r, rIdx) => (
                                <li key={rIdx} className={isMatched ? 'text-emerald-300/90' : 'text-slate-400'}>
                                  {r}
                                </li>
                              ))}
                            </ul>
                            {evalInfo.raw_syntax && (
                              <div className="mt-2 pt-1 border-t border-slate-800 text-[10px] text-slate-500">
                                Sintaxe Original: <code>{evalInfo.raw_syntax}</code>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
