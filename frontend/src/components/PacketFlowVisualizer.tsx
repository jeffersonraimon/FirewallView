import React from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  Filter,
  Layers,
  Network,
  RotateCw,
  CornerDownRight,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import { SimulationResult, StageEvaluation } from '../types';

interface PacketFlowVisualizerProps {
  simulationResult: SimulationResult | null;
  selectedStage: string | null;
  onSelectStage: (stageId: string | null) => void;
}

export const PacketFlowVisualizer: React.FC<PacketFlowVisualizerProps> = ({
  simulationResult,
  selectedStage,
  onSelectStage
}) => {
  if (!simulationResult) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-8 text-center text-slate-500 mb-6">
        <Network className="w-10 h-10 mx-auto mb-2 text-slate-600 animate-pulse" />
        <p>Injete um pacote e clique em "Simular Pacote" para visualizar o fluxo detalhado pelas etapas do Firewall.</p>
      </div>
    );
  }

  const { verdict, final_action, stages, flow_path, packet_in, packet_out, summary, matched_rule_id } = simulationResult;
  const isAccepted = verdict === 'ACCEPT';

  const hasDNat = packet_in.dst_ip !== packet_out.dst_ip || packet_in.dst_port !== packet_out.dst_port;
  const hasSNat = packet_in.src_ip !== packet_out.src_ip;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-xl mb-6">
      {/* Top Banner Verdict */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-4 rounded-xl mb-5 bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-slate-800">
        <div className="flex items-center gap-3.5">
          <div
            className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${
              isAccepted
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
            }`}
          >
            {isAccepted ? <ShieldCheck className="w-7 h-7" /> : <ShieldAlert className="w-7 h-7" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                  isAccepted
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'bg-rose-950 text-rose-300 border border-rose-800'
                }`}
              >
                {isAccepted ? 'PERMITIDO' : 'BLOQUEADO'}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                {final_action}
              </span>
            </div>
            <p className="text-sm font-medium text-slate-200 mt-1">
              {summary}
            </p>
          </div>
        </div>

        {/* NAT Transformations badge if any */}
        {(hasDNat || hasSNat) && (
          <div className="bg-amber-950/40 border border-amber-800/60 rounded-lg p-2.5 text-xs text-amber-200">
            <span className="font-semibold block text-amber-400 text-[10px] uppercase tracking-wider mb-0.5">
              Transformações NAT Aplicadas:
            </span>
            {hasDNat && (
              <div className="font-mono text-[11px]">
                DNAT: {packet_in.dst_ip}:{packet_in.dst_port} → {packet_out.dst_ip}:{packet_out.dst_port}
              </div>
            )}
            {hasSNat && (
              <div className="font-mono text-[11px]">
                SNAT: {packet_in.src_ip} → {packet_out.src_ip}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Interactive Horizontal Pipeline Visualizer */}
      <div className="mb-2">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Fluxo do Pacote no Pipeline de Decisão
            </h3>
          </div>
          {selectedStage && (
            <button
              onClick={() => onSelectStage(null)}
              className="text-xs text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
            >
              Limpar Filtro de Estágio
            </button>
          )}
        </div>

        {/* Stages Grid / Flow Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-8 gap-2">
          {stages.map((stage, idx) => {
            const isDroppedInStage = stage.stage_verdict === 'DROPPED' || stage.stage_verdict === 'REJECTED';
            const isSelected = selectedStage === stage.stage_id;
            const rulesCount = stage.evaluated_rules.length;
            const hasMatchedRule = stage.evaluated_rules.some(r => r.matched);

            let statusBorder = 'border-slate-800';
            let statusBg = 'bg-slate-950/60';
            let statusText = 'text-slate-400';

            if (isDroppedInStage) {
              statusBorder = 'border-rose-500/80 shadow-rose-950/40 shadow-lg';
              statusBg = 'bg-rose-950/30';
              statusText = 'text-rose-400';
            } else if (hasMatchedRule) {
              statusBorder = 'border-cyan-500/60 shadow-cyan-950/30 shadow-lg';
              statusBg = 'bg-cyan-950/20';
              statusText = 'text-cyan-400';
            }

            if (isSelected) {
              statusBorder = 'border-cyan-400 ring-2 ring-cyan-500/30';
            }

            return (
              <button
                key={stage.stage_id}
                onClick={() => onSelectStage(isSelected ? null : stage.stage_id)}
                className={`flex flex-col justify-between text-left p-2.5 rounded-xl border transition-all ${statusBorder} ${statusBg} hover:border-slate-600 relative group`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 uppercase">
                      #{idx + 1}
                    </span>
                    {isDroppedInStage ? (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    ) : hasMatchedRule ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : (
                      <div className="w-2 h-2 rounded-full bg-slate-700 shrink-0" />
                    )}
                  </div>

                  <span className="text-xs font-semibold text-slate-200 block truncate">
                    {stage.stage_title.split('-')[0].trim()}
                  </span>
                  <span className="text-[10px] text-slate-400 block font-mono truncate">
                    {stage.stage_title.split('-')[1]?.trim() || stage.chain}
                  </span>
                </div>

                <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px]">
                  <span className="text-slate-500">
                    {rulesCount} {rulesCount === 1 ? 'regra' : 'regras'}
                  </span>
                  {hasMatchedRule && (
                    <span className="text-emerald-400 font-medium">Match</span>
                  )}
                  {isDroppedInStage && (
                    <span className="text-rose-400 font-bold">Drop</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
