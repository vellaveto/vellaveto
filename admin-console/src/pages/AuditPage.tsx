import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, RefreshCw, Search, CheckCircle } from "lucide-react";
import { DataTable, type Column } from "../components/common/DataTable";
import { VerdictBadge } from "../components/common/VerdictBadge";
import * as api from "../api/client";
import type { AuditEntry, AuditSearchParams } from "../types/api";

export function AuditPage() {
  const [params, setParams] = useState<AuditSearchParams>({ limit: 50 });
  const [toolFilter, setToolFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");

  const query = useQuery({
    queryKey: ["audit", params],
    queryFn: () => api.searchAudit(params),
    refetchInterval: 10_000,
  });

  const verifyQ = useQuery({
    queryKey: ["audit-verify"],
    queryFn: api.verifyAudit,
    enabled: false,
  });

  const handleSearch = useCallback(() => {
    const next: AuditSearchParams = { ...params, limit: 50 };
    if (toolFilter) next.tool = toolFilter;
    if (verdictFilter) next.verdict = verdictFilter as AuditSearchParams["verdict"];
    setParams(next);
  }, [params, toolFilter, verdictFilter]);

  const handleExport = useCallback(async (format: "cef" | "jsonl" | "csv") => {
    const data = await api.exportAudit(format);
    const blob = new Blob([data], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-export.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const columns: Column<AuditEntry>[] = [
    {
      key: "timestamp",
      header: "Time",
      width: "160px",
      render: (e) => new Date(e.timestamp).toLocaleString(),
    },
    {
      key: "verdict",
      header: "Verdict",
      width: "100px",
      render: (e) => <VerdictBadge verdict={e.verdict} />,
    },
    { key: "tool", header: "Tool", render: (e) => e.action.tool },
    { key: "function", header: "Function", render: (e) => e.action.function },
    {
      key: "reason",
      header: "Details",
      render: (e) => {
        const v = e.verdict;
        if (v === "Allow") return "";
        if (typeof v === "object" && "Deny" in v) return v.Deny.reason;
        if (typeof v === "object" && "RequireApproval" in v)
          return v.RequireApproval.reason;
        return "";
      },
    },
    {
      key: "hash",
      header: "Hash",
      width: "120px",
      render: (e) => <code className="hash">{e.entry_hash.slice(0, 12)}</code>,
    },
  ];

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">Audit Log</h2>
        <div className="page-actions">
          <button
            className="btn btn--outline"
            onClick={() => verifyQ.refetch()}
            title="Verify audit chain integrity"
          >
            <CheckCircle size={16} />
            Verify
          </button>
          <button className="btn btn--outline" onClick={() => handleExport("jsonl")}>
            <Download size={16} />
            JSONL
          </button>
          <button className="btn btn--outline" onClick={() => handleExport("cef")}>
            <Download size={16} />
            CEF
          </button>
          <button className="btn btn--outline" onClick={() => handleExport("csv")}>
            <Download size={16} />
            CSV
          </button>
        </div>
      </div>

      {verifyQ.data && (
        <div
          className={`alert ${verifyQ.data.valid ? "alert--success" : "alert--danger"}`}
        >
          {verifyQ.data.valid
            ? "Audit chain integrity verified"
            : `Integrity check failed: ${verifyQ.data.errors.join(", ")}`}
        </div>
      )}

      <div className="filter-bar">
        <input
          type="text"
          className="input"
          placeholder="Filter by tool..."
          value={toolFilter}
          onChange={(e) => setToolFilter(e.target.value)}
        />
        <select
          className="input"
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
        >
          <option value="">All verdicts</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="require_approval">Approval</option>
        </select>
        <button className="btn btn--primary" onClick={handleSearch}>
          <Search size={16} />
          Search
        </button>
        <button className="btn btn--ghost" onClick={() => query.refetch()}>
          <RefreshCw size={16} />
        </button>
      </div>

      <DataTable
        columns={columns}
        data={query.data ?? []}
        keyFn={(e) => e.id}
        emptyMessage="No audit entries match the current filters"
      />
    </div>
  );
}
