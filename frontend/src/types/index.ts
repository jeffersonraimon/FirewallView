export interface RuleCondition {
  src_address?: string;
  dst_address?: string;
  src_address_list?: string;
  dst_address_list?: string;
  protocol?: string;
  src_port?: string;
  dst_port?: string;
  port?: string;
  in_interface?: string;
  out_interface?: string;
  connection_state?: string[];
  tcp_flags?: string[];
  packet_mark?: string;
  negate_src_address?: boolean;
  negate_dst_address?: boolean;
  negate_src_address_list?: boolean;
  negate_dst_address_list?: boolean;
  negate_protocol?: boolean;
  negate_src_port?: boolean;
  negate_dst_port?: boolean;
  negate_port?: boolean;
  negate_in_interface?: boolean;
  negate_out_interface?: boolean;
}

export interface FirewallRule {
  id: string;
  order: number;
  table: string; // filter, nat, mangle, raw
  chain: string; // forward, input, output, prerouting, postrouting, dstnat, srcnat, etc.
  action: string; // accept, drop, reject, fasttrack-connection, jump, return, dst-nat, src-nat, masquerade, redirect, etc.
  target_chain?: string;
  nat_to_addresses?: string;
  nat_to_ports?: string;
  mark_value?: string;
  conditions: RuleCondition;
  comment?: string;
  disabled: boolean;
  raw_syntax?: string;
}

export interface AddressListEntry {
  id?: string;
  address: string;
  comment?: string;
  disabled: boolean;
}

export interface AddressList {
  name: string;
  entries: AddressListEntry[];
}

export interface SimulationPacket {
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  in_interface?: string;
  out_interface?: string;
  connection_state: string; // new, established, related, invalid, untracked
  tcp_flags: string[]; // syn, ack, fin, rst, etc.
  packet_marks: string[];
  flow_type?: 'forward' | 'input' | 'output';
  is_router_traffic?: boolean;
}

export interface RuleEvaluation {
  rule_id: string;
  rule_order: number;
  table: string;
  chain: string;
  action: string;
  matched: boolean;
  reasons: string[];
  applied_effect?: string;
  terminated: boolean;
  comment?: string;
  raw_syntax?: string;
}

export interface StageEvaluation {
  stage_id: string;
  stage_title: string;
  table: string;
  chain: string;
  evaluated_rules: RuleEvaluation[];
  stage_verdict: string; // CONTINUE, ACCEPTED, DROPPED, REJECTED
  notes?: string;
}

export interface SimulationResult {
  verdict: string; // ACCEPT, DROP, REJECT
  final_action: string;
  packet_in: SimulationPacket;
  packet_out: SimulationPacket;
  stages: StageEvaluation[];
  flow_path: string[];
  summary: string;
  matched_rule_id?: string;
}
