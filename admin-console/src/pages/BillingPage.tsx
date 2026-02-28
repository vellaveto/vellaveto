// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useQuery } from "@tanstack/react-query";
import { CreditCard } from "lucide-react";
import { StatusCard } from "../components/common/StatusCard";
import * as api from "../api/client";

export function BillingPage() {
  const licenseQ = useQuery({ queryKey: ["license"], queryFn: api.getLicense });
  const usageQ = useQuery({
    queryKey: ["usage", "default"],
    queryFn: () => api.getUsage("default"),
    refetchInterval: 30_000,
  });
  const quotaQ = useQuery({
    queryKey: ["quotas", "default"],
    queryFn: () => api.getQuotas("default"),
    refetchInterval: 30_000,
  });

  const usage = usageQ.data;
  const quota = quotaQ.data;
  const license = licenseQ.data;

  const usagePct = quota ? Math.round((quota.used / Math.max(quota.limit, 1)) * 100) : 0;

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <CreditCard size={20} />
          Billing & Usage
        </h2>
      </div>

      <div className="card-grid">
        <StatusCard
          title="License Tier"
          value={license?.tier ?? "loading..."}
          variant="default"
        />
        <StatusCard
          title="Evaluations (period)"
          value={usage?.evaluations ?? 0}
          subtitle={`${usage?.allowed ?? 0} allow / ${usage?.denied ?? 0} deny`}
        />
        <StatusCard
          title="Quota Used"
          value={`${usagePct}%`}
          subtitle={quota ? `${quota.used} / ${quota.limit}` : undefined}
          variant={usagePct >= 90 ? "danger" : usagePct >= 70 ? "warning" : "success"}
        />
        <StatusCard
          title="Remaining"
          value={quota?.remaining ?? 0}
          variant="default"
        />
      </div>

      {usage && (
        <section className="section">
          <h3 className="section-title">Usage Breakdown</h3>
          <div className="usage-grid">
            <div className="usage-item">
              <span className="usage-label">Policies</span>
              <span className="usage-value">{usage.policies}</span>
            </div>
            <div className="usage-item">
              <span className="usage-label">Approvals</span>
              <span className="usage-value">{usage.approvals}</span>
            </div>
            <div className="usage-item">
              <span className="usage-label">Audit Entries</span>
              <span className="usage-value">{usage.audit_entries}</span>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
