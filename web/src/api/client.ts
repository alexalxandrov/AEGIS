import type {
  AIHistoryItem,
  AIResponse,
  Asset,
  AssetDetail,
  ChangeEvent,
  DiffResult,
  Exclusion,
  Finding,
  GraphData,
  Org,
  Overview,
  Paginated,
  RiskOverview,
  ScanCompare,
  ScanRun,
  SearchResult,
  Seed,
  Settings,
  SourceRegistry,
  SystemInfo,
  OllamaStatus,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public body?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = await res.text();
    }
    const msg =
      typeof body === "object" && body && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : res.statusText;
    throw new ApiError(msg || `HTTP ${res.status}`, res.status, body);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return res.json() as Promise<T>;
  }
  return res.text() as unknown as T;
}

export const api = {
  health: () => request<{ ok: boolean; version: string }>("/api/health"),
  system: () => request<SystemInfo>("/api/system"),

  listOrgs: () => request<Org[]>("/api/orgs"),
  createOrg: (name: string) =>
    request<Org>("/api/orgs", { method: "POST", body: JSON.stringify({ name }) }),
  getOrg: (id: number) => request<Org>(`/api/orgs/${id}`),
  listSeeds: (orgId: number) => request<Seed[]>(`/api/orgs/${orgId}/seeds`),
  addSeed: (orgId: number, body: { kind: string; value: string; verified?: boolean }) =>
    request<{ seed_ok: boolean; asset_id: number; scope: string }>(
      `/api/orgs/${orgId}/seeds`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  overview: (orgId: number, hours = 168) =>
    request<Overview>(`/api/orgs/${orgId}/overview?hours=${hours}`),

  listAssets: (orgId: number, params: Record<string, string | number>) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== "" && v !== undefined) q.set(k, String(v));
    });
    return request<Paginated<Asset>>(`/api/orgs/${orgId}/assets?${q}`);
  },
  getAsset: (id: number) => request<AssetDetail>(`/api/assets/${id}`),
  setAssetScope: (id: number, body: { scope: string; note?: string; method?: string }) =>
    request<Asset>(`/api/assets/${id}/scope`, { method: "POST", body: JSON.stringify(body) }),

  graph: (orgId: number, limit: number, kinds?: string) => {
    const q = new URLSearchParams({ limit: String(limit) });
    if (kinds) q.set("kinds", kinds);
    return request<GraphData>(`/api/orgs/${orgId}/graph?${q}`);
  },

  listFindings: (orgId: number, params: Record<string, string | number>) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== "" && v !== undefined) q.set(k, String(v));
    });
    return request<Paginated<Finding>>(`/api/orgs/${orgId}/findings?${q}`);
  },
  getFinding: (id: number) => request<Finding>(`/api/findings/${id}`),
  setFindingState: (id: number, state: string, note = "") =>
    request<{ ok: boolean }>(`/api/findings/${id}/state`, {
      method: "POST",
      body: JSON.stringify({ state, note }),
    }),

  orgRisk: (orgId: number) => request<RiskOverview>(`/api/orgs/${orgId}/risk`),

  changes: (orgId: number, hours: number, page = 1, pageSize = 50) =>
    request<Paginated<ChangeEvent & { asset_value?: string }>>(
      `/api/orgs/${orgId}/changes?hours=${hours}&page=${page}&page_size=${pageSize}`,
    ),
  diff: (orgId: number, hours: number) =>
    request<DiffResult>(`/api/orgs/${orgId}/diff?hours=${hours}`),
  baseline: (orgId: number) =>
    request<{ baselined: number }>(`/api/orgs/${orgId}/baseline`, { method: "POST" }),
  compareScans: (orgId: number, a: number, b: number) =>
    request<ScanCompare>(`/api/orgs/${orgId}/scans/compare?a=${a}&b=${b}`),

  listScans: (orgId: number, limit = 50) =>
    request<ScanRun[]>(`/api/orgs/${orgId}/scans?limit=${limit}`),
  createScan: (body: {
    org_id: number;
    mode: string;
    sources?: string[];
    limit?: number;
    brute?: boolean;
    wayback?: boolean;
    hours?: number;
    confirm_active?: boolean;
  }) => request<ScanRun>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  getScan: (id: number) => request<ScanRun>(`/api/scans/${id}`),
  cancelScan: (id: number) => request<ScanRun>(`/api/scans/${id}/cancel`, { method: "POST" }),

  listSources: () => request<SourceRegistry[]>("/api/sources"),
  refreshSources: (network = true) =>
    request<{ results: unknown; sources: SourceRegistry[] }>(
      `/api/sources/refresh?network=${network ? "true" : "false"}`,
      { method: "POST" },
    ),

  listExclusions: (orgId: number) => request<Exclusion[]>(`/api/orgs/${orgId}/exclusions`),
  addExclusion: (orgId: number, body: { kind: string; pattern: string; note?: string }) =>
    request<Exclusion[]>(`/api/orgs/${orgId}/exclusions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteExclusion: (id: number) =>
    request<{ ok: boolean }>(`/api/exclusions/${id}`, { method: "DELETE" }),

  getSettings: () => request<Settings>("/api/settings"),
  putSetting: (key: string, value: unknown) =>
    request<{ key: string; value: unknown }>(`/api/settings/${key}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
    }),

  aiStatus: () => request<OllamaStatus>("/api/ai/status"),
  aiAsk: (orgId: number, question: string) =>
    request<AIResponse>("/api/ai/ask", {
      method: "POST",
      body: JSON.stringify({ org_id: orgId, question }),
    }),
  aiExplain: (findingId: number) =>
    request<AIResponse>(`/api/ai/explain/${findingId}`, { method: "POST" }),
  aiHistory: (orgId: number, limit = 50) =>
    request<AIHistoryItem[]>(`/api/ai/history?org_id=${orgId}&limit=${limit}`),

  search: (q: string, orgId?: number) => {
    const params = new URLSearchParams({ q });
    if (orgId) params.set("org_id", String(orgId));
    return request<SearchResult>(`/api/search?${params}`);
  },

  reportUrl: (orgId: number, fmt: "json" | "csv" | "md", hours = 168) =>
    `/api/orgs/${orgId}/report?fmt=${fmt}&hours=${hours}`,
  exportAssetsUrl: (orgId: number) => `/api/orgs/${orgId}/export/assets.csv`,

  actionLog: (limit = 100) => request<unknown[]>(`/api/action-log?limit=${limit}`),
};
