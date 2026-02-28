// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { StatusCard } from "../components/common/StatusCard";
import * as api from "../api/client";

export function CompliancePage() {
  const complianceQ = useQuery({
    queryKey: ["compliance"],
    queryFn: api.getComplianceStatus,
  });

  const frameworks = complianceQ.data?.frameworks ?? {};

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <Activity size={20} />
          Compliance Status
        </h2>
      </div>

      {Object.keys(frameworks).length === 0 ? (
        <div className="empty-state">No compliance frameworks configured</div>
      ) : (
        <div className="card-grid card-grid--wide">
          {Object.entries(frameworks).map(([key, fw]) => {
            const pct = Math.round(fw.score * 100);
            return (
              <div key={key} className="compliance-card">
                <StatusCard
                  title={fw.name}
                  value={`${pct}%`}
                  subtitle={`${fw.passing}/${fw.total} controls passing`}
                  variant={pct >= 80 ? "success" : pct >= 50 ? "warning" : "danger"}
                />
                <div className="compliance-bar">
                  <div
                    className="compliance-bar__fill"
                    style={{ width: `${pct}%` }}
                    data-variant={
                      pct >= 80 ? "success" : pct >= 50 ? "warning" : "danger"
                    }
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
