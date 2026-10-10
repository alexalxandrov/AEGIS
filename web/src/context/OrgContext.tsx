import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Org } from "../api/types";

const ORG_KEY = "aegis-org-id";

const OrgContext = createContext<{
  orgId: number | null;
  org: Org | null;
  orgs: Org[];
  setOrgId: (id: number) => void;
  isLoading: boolean;
  refetchOrgs: () => void;
} | null>(null);

export function OrgProvider({ children }: { children: ReactNode }) {
  const { data: orgs = [], isLoading, refetch } = useQuery({
    queryKey: ["orgs"],
    queryFn: api.listOrgs,
  });

  const [orgId, setOrgIdState] = useState<number | null>(() => {
    const raw = localStorage.getItem(ORG_KEY);
    return raw ? Number(raw) : null;
  });

  useEffect(() => {
    if (!orgs.length) {
      setOrgIdState(null);
      localStorage.removeItem(ORG_KEY);
      return;
    }
    const exists = orgId && orgs.some((o) => o.id === orgId);
    if (!exists) {
      const next = orgs[0].id;
      setOrgIdState(next);
      localStorage.setItem(ORG_KEY, String(next));
    }
  }, [orgs, orgId]);

  const setOrgId = useCallback((id: number) => {
    setOrgIdState(id);
    localStorage.setItem(ORG_KEY, String(id));
  }, []);

  const org = useMemo(() => orgs.find((o) => o.id === orgId) ?? null, [orgs, orgId]);

  const value = useMemo(
    () => ({
      orgId,
      org,
      orgs,
      setOrgId,
      isLoading,
      refetchOrgs: refetch,
    }),
    [orgId, org, orgs, setOrgId, isLoading, refetch],
  );

  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg() {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error("useOrg outside provider");
  return ctx;
}

export function useRequireOrg() {
  const { orgId, org, ...rest } = useOrg();
  return { orgId: orgId!, org: org!, ...rest };
}
