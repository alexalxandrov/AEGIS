export interface Org {
  id: number;
  name: string;
  created?: number;
  assets?: number;
  findings_open?: number;
}

export interface Seed {
  id: number;
  org_id: number;
  kind: string;
  value: string;
  verified: number;
  created?: number;
}

export interface Asset {
  id: number;
  org_id: number;
  kind: string;
  value: string;
  scope: string;
  existence_conf?: number;
  attribution_conf?: number;
  first_seen?: number;
  last_seen?: number;
}

export interface AssetDetail extends Asset {
  observations: Observation[];
  findings: Finding[];
  edges: Edge[];
  scope_history: ScopeDecision[];
}

export interface Observation {
  id: number;
  asset_id: number;
  source: string;
  key: string;
  evidence_hash?: string;
  payload_json?: string;
  created?: number;
}

export interface Finding {
  id: number;
  asset_id: number;
  kind: string;
  severity: string;
  state: string;
  text: string;
  note?: string;
  obs_ids?: string;
  asset_value?: string;
  asset_kind?: string;
  asset_scope?: string;
  org_id?: number;
  observations?: Observation[];
  risk?: RiskAssessment;
}

export interface Edge {
  id: number;
  src: number;
  dst: number;
  kind: string;
  src_value?: string;
  src_kind?: string;
  dst_value?: string;
  dst_kind?: string;
  last_seen?: number;
}

export interface ScopeDecision {
  id: number;
  asset_id: number;
  old_scope: string;
  new_scope: string;
  actor?: string;
  method?: string;
  note?: string;
  created?: number;
}

export interface Paginated<T> {
  total: number;
  page?: number;
  page_size?: number;
  items: T[];
}

export interface Overview {
  org_id: number;
  assets_total: number;
  scopes: Record<string, number>;
  kinds: Record<string, number>;
  risk: RiskOverview;
  changes_period: number;
  last_scan: ScanRun | null;
  top_findings: Finding[];
  events: ChangeEvent[];
  sources: { available: number; total: number };
  growth: { t: number; new_assets: number }[];
  ollama: OllamaStatus;
}

export interface RiskOverview {
  score?: number;
  level?: string;
  open_findings?: number;
  by_severity?: Record<string, number>;
  factors?: unknown[];
}

export interface RiskAssessment {
  score?: number;
  level?: string;
  factors?: { name: string; value?: unknown; delta?: number }[];
  rationale?: string;
}

export interface ChangeEvent {
  id: number;
  org_id: number;
  asset_id?: number;
  kind: string;
  text?: string;
  created: number;
  asset_value?: string;
  run_id?: number;
}

export interface ScanRun {
  id: number;
  org_id: number;
  mode: string;
  status: string;
  stage: string;
  message?: string;
  error?: string;
  created?: number;
  finished?: number;
  progress_done?: number;
  progress_total?: number;
  sources?: string[];
  stats?: Record<string, unknown>;
  tasks?: ScanTask[];
  cancel_requested?: number;
}

export interface ScanTask {
  id: number;
  run_id: number;
  source: string;
  status: string;
  error?: string;
  started?: number;
  finished?: number;
}

export interface SourceRegistry {
  name: string;
  available: number;
  last_check?: number;
  last_error?: string;
  description?: string;
}

export interface Exclusion {
  id: number;
  org_id: number;
  kind: string;
  pattern: string;
  note?: string;
  created?: number;
}

export interface GraphData {
  nodes: Asset[];
  edges: Edge[];
  truncated: boolean;
  depth: number;
}

export interface SearchResult {
  assets: Pick<Asset, "id" | "org_id" | "kind" | "value" | "scope">[];
  findings: {
    id: number;
    kind: string;
    severity: string;
    text: string;
    org_id: number;
    value: string;
  }[];
}

export interface OllamaStatus {
  available: boolean;
  url?: string;
  models: string[];
  configured_model?: string;
  preferred_present?: boolean;
  warning?: string | null;
}

export interface AIResponse {
  answer: string;
  cites: string[];
  insufficient?: boolean;
  model?: string | null;
  error?: string | null;
}

export interface AIHistoryItem {
  id: number;
  org_id: number;
  kind: string;
  question?: string;
  answer?: string;
  cites_json?: string;
  model?: string;
  created?: number;
}

export interface SystemInfo {
  version: string;
  data_dir: string;
  db_path: string;
  model: string;
  ollama: OllamaStatus;
  settings: Record<string, unknown>;
}

export interface Settings {
  theme?: string;
  scan_limit?: number;
  default_hours?: number;
  graph_limit?: number;
}

export interface DiffResult {
  events: ChangeEvent[];
  count: number;
}

export interface ScanCompare {
  only_a: string[];
  only_b: string[];
  both: string[];
  run_a: ScanRun;
  run_b: ScanRun;
}
