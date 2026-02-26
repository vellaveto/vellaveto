import { useQuery } from "@tanstack/react-query";
import { StatusCard } from "../components/common/StatusCard";
import { VerdictBadge } from "../components/common/VerdictBadge";
import * as api from "../api/client";
import type { AuditEntry, Verdict } from "../types/api";

export function DashboardPage() {
  const healthQ = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 10_000 });
  const auditQ = useQuery({
    queryKey: ["audit-recent"],
    queryFn: () => api.searchAudit({ limit: 20 }),
    refetchInterval: 5_000,
  });
  const complianceQ = useQuery({ queryKey: ["compliance"], queryFn: api.getComplianceStatus });
  const approvalsQ = useQuery({ queryKey: ["approvals"], queryFn: api.listPendingApprovals });

  const entries: AuditEntry[] = auditQ.data ?? [];
  const allowCount = entries.filter((e) => e.verdict === "Allow").length;
  const denyCount = entries.filter((e) => typeof e.verdict === "object" && "Deny" in e.verdict).length;

  const frameworks = complianceQ.data?.frameworks ?? {};
  const avgScore = Object.values(frameworks).length > 0
    ? Math.round(
        Object.values(frameworks).reduce((s, f) => s + f.score, 0) /
          Object.values(frameworks).length * 100,
      )
    : 0;

  return (
    <div className="page">
      <h2 className="page-title">Dashboard</h2>

      <div className="card-grid">
        <StatusCard
          title="Server Status"
          value={healthQ.data?.status ?? "loading..."}
          subtitle={healthQ.data ? `v${healthQ.data.version}` : undefined}
          variant={healthQ.data?.status === "ok" ? "success" : "warning"}
        />
        <StatusCard
          title="Recent Evaluations"
          value={entries.length}
          subtitle={`${allowCount} allow / ${denyCount} deny`}
        />
        <StatusCard
          title="Pending Approvals"
          value={approvalsQ.data?.length ?? 0}
          variant={(approvalsQ.data?.length ?? 0) > 0 ? "warning" : "default"}
        />
        <StatusCard
          title="Compliance Score"
          value={`${avgScore}%`}
          subtitle={`${Object.keys(frameworks).length} frameworks`}
          variant={avgScore >= 80 ? "success" : avgScore >= 50 ? "warning" : "danger"}
        />
      </div>

      <section className="section">
        <h3 className="section-title">Recent Verdicts</h3>
        <div className="verdict-stream">
          {entries.length === 0 && <div className="empty-state">No recent evaluations</div>}
          {entries.map((entry) => (
            <div key={entry.id} className="verdict-row">
              <VerdictBadge verdict={entry.verdict} />
              <span className="verdict-tool">{entry.action.tool}</span>
              <span className="verdict-fn">{entry.action.function}</span>
              <span className="verdict-time">
                {formatTime(entry.timestamp)}
              </span>
              {isDeny(entry.verdict) && (
                <span className="verdict-reason">
                  {(entry.verdict as { Deny: { reason: string } }).Deny.reason}
                </span>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function isDeny(v: Verdict): boolean {
  return typeof v === "object" && "Deny" in v;
}

function formatTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return ts;
  }
}
