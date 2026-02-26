import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import * as api from "../api/client";

export function GovernancePage() {
  const shadowQ = useQuery({
    queryKey: ["shadow-report"],
    queryFn: api.getShadowReport,
  });

  const unapprovedQ = useQuery({
    queryKey: ["unapproved-tools"],
    queryFn: api.getUnapprovedTools,
  });

  const breakersQ = useQuery({
    queryKey: ["circuit-breakers"],
    queryFn: api.listCircuitBreakers,
  });

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <AlertTriangle size={20} />
          Governance
        </h2>
      </div>

      <section className="section">
        <h3 className="section-title">Circuit Breakers</h3>
        {(breakersQ.data ?? []).length === 0 ? (
          <div className="empty-state">All circuit breakers closed (healthy)</div>
        ) : (
          <div className="card-grid">
            {(breakersQ.data ?? []).map((cb) => (
              <div
                key={cb.tool}
                className={`circuit-card circuit-card--${cb.state}`}
              >
                <div className="circuit-card__tool">{cb.tool}</div>
                <div className="circuit-card__state">{cb.state}</div>
                <div className="circuit-card__failures">
                  {cb.failure_count} failures
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="section">
        <h3 className="section-title">Shadow Agent Report</h3>
        <pre className="code-block">
          {shadowQ.data ? JSON.stringify(shadowQ.data, null, 2) : "Loading..."}
        </pre>
      </section>

      <section className="section">
        <h3 className="section-title">Unapproved Tools</h3>
        <pre className="code-block">
          {unapprovedQ.data
            ? JSON.stringify(unapprovedQ.data, null, 2)
            : "Loading..."}
        </pre>
      </section>
    </div>
  );
}
