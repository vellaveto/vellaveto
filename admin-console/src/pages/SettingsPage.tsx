// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useQuery } from "@tanstack/react-query";
import { Settings } from "lucide-react";
import * as api from "../api/client";

export function SettingsPage() {
  const deployQ = useQuery({
    queryKey: ["deployment"],
    queryFn: api.getDeploymentInfo,
  });

  const deploy = deployQ.data;

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <Settings size={20} />
          Settings
        </h2>
      </div>

      <section className="section">
        <h3 className="section-title">Deployment Info</h3>
        {deploy ? (
          <div className="settings-grid">
            <div className="setting-item">
              <span className="setting-label">Version</span>
              <span className="setting-value">{deploy.version}</span>
            </div>
            <div className="setting-item">
              <span className="setting-label">Cluster ID</span>
              <span className="setting-value">
                {deploy.cluster_id ?? "standalone"}
              </span>
            </div>
            <div className="setting-item">
              <span className="setting-label">Nodes</span>
              <span className="setting-value">{deploy.node_count}</span>
            </div>
            <div className="setting-item">
              <span className="setting-label">Leader</span>
              <span className="setting-value">
                {deploy.leader ?? "self"}
              </span>
            </div>
          </div>
        ) : (
          <div className="empty-state">Loading deployment info...</div>
        )}
      </section>

      <section className="section">
        <h3 className="section-title">Server Connection</h3>
        <div className="settings-grid">
          <div className="setting-item">
            <span className="setting-label">Server URL</span>
            <span className="setting-value">
              <code>{api.getBaseUrl() || "(not configured)"}</code>
            </span>
          </div>
        </div>
      </section>
    </div>
  );
}
