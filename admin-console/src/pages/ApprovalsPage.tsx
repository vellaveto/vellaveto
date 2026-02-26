import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X, ShieldCheck } from "lucide-react";
import { DataTable, type Column } from "../components/common/DataTable";
import * as api from "../api/client";
import type { ApprovalRequest } from "../types/api";

export function ApprovalsPage() {
  const queryClient = useQueryClient();

  const approvalsQ = useQuery({
    queryKey: ["approvals"],
    queryFn: api.listPendingApprovals,
    refetchInterval: 5_000,
  });

  const approveMut = useMutation({
    mutationFn: api.approveRequest,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["approvals"] }),
  });

  const denyMut = useMutation({
    mutationFn: api.denyRequest,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["approvals"] }),
  });

  const columns: Column<ApprovalRequest>[] = [
    {
      key: "created",
      header: "Time",
      width: "160px",
      render: (a) => new Date(a.created_at).toLocaleString(),
    },
    { key: "tool", header: "Tool", render: (a) => a.action.tool },
    { key: "function", header: "Function", render: (a) => a.action.function },
    { key: "reason", header: "Reason", render: (a) => a.reason },
    {
      key: "requester",
      header: "Requester",
      width: "140px",
      render: (a) => a.requested_by ?? "unknown",
    },
    {
      key: "actions",
      header: "",
      width: "120px",
      render: (a) => (
        <div className="action-buttons">
          <button
            className="btn btn--small btn--success"
            onClick={() => approveMut.mutate(a.id)}
            disabled={approveMut.isPending}
            title="Approve"
          >
            <Check size={14} />
          </button>
          <button
            className="btn btn--small btn--danger"
            onClick={() => denyMut.mutate(a.id)}
            disabled={denyMut.isPending}
            title="Deny"
          >
            <X size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <ShieldCheck size={20} />
          Pending Approvals
        </h2>
      </div>

      <DataTable
        columns={columns}
        data={approvalsQ.data ?? []}
        keyFn={(a) => a.id}
        emptyMessage="No pending approval requests"
      />
    </div>
  );
}
