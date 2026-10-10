import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import { Moon, Sun } from "lucide-react";

export function Onboarding() {
  const qc = useQueryClient();
  const { theme, toggle } = useTheme();
  const [name, setName] = useState("");
  const [seedKind, setSeedKind] = useState("domain");
  const [seedValue, setSeedValue] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: async () => {
      const org = await api.createOrg(name.trim());
      if (seedValue.trim()) {
        await api.addSeed(org.id, {
          kind: seedKind,
          value: seedValue.trim(),
          verified: true,
        });
      }
      return org;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["orgs"] });
    },
    onError: (e) => {
      setErr(e instanceof ApiError ? e.message : "Failed to create organization");
    },
  });

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-[var(--bg)]">
      <button type="button" className="absolute top-4 right-4 btn-ghost p-2" onClick={toggle}>
        {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
      </button>
      <div className="panel max-w-lg w-full p-8 space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Welcome to AEGIS</h1>
          <p className="text-sm text-[var(--text-muted)] mt-2">
            Create your first organization and add a verified seed to begin mapping external attack
            surface. All data stays local.
          </p>
        </div>
        <div className="space-y-4">
          <div>
            <label className="label" htmlFor="org-name">
              Organization name
            </label>
            <input
              id="org-name"
              className="input mt-1"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Corp"
            />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-1">
              <label className="label" htmlFor="seed-kind">
                Seed kind
              </label>
              <select
                id="seed-kind"
                className="input mt-1"
                value={seedKind}
                onChange={(e) => setSeedKind(e.target.value)}
              >
                <option value="domain">domain</option>
                <option value="asn">asn</option>
                <option value="cidr">cidr</option>
                <option value="ip">ip</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="label" htmlFor="seed-value">
                Seed value (verified)
              </label>
              <input
                id="seed-value"
                className="input mt-1 font-mono text-sm"
                value={seedValue}
                onChange={(e) => setSeedValue(e.target.value)}
                placeholder="example.com"
              />
            </div>
          </div>
          {err && <p className="text-sm text-red-400">{err}</p>}
          <button
            type="button"
            className="btn-primary w-full"
            disabled={!name.trim() || create.isPending}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Creating…" : "Create organization"}
          </button>
        </div>
      </div>
    </div>
  );
}
