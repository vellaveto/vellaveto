import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { SettingsPage } from "./SettingsPage";
import { createWrapper } from "../test/wrapper";

// Mock the API client
vi.mock("../api/client", () => ({
  getDeploymentInfo: vi.fn().mockResolvedValue({
    version: "4.0.0",
    cluster_id: "cluster-1",
    node_count: 3,
    leader: "node-0",
  }),
  getBaseUrl: vi.fn().mockReturnValue("http://localhost:8080"),
}));

describe("SettingsPage", () => {
  it("renders Settings title", () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Settings")).toBeInTheDocument();
  });

  it("shows deployment info section", () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Deployment Info")).toBeInTheDocument();
  });

  it("displays version after loading", async () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    await waitFor(() => {
      expect(screen.getByText("4.0.0")).toBeInTheDocument();
    });
  });

  it("displays cluster ID", async () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    await waitFor(() => {
      expect(screen.getByText("cluster-1")).toBeInTheDocument();
    });
  });

  it("displays node count", async () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    await waitFor(() => {
      expect(screen.getByText("3")).toBeInTheDocument();
    });
  });

  it("shows server connection section", () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Server Connection")).toBeInTheDocument();
  });

  it("displays server URL", () => {
    render(<SettingsPage />, { wrapper: createWrapper() });
    expect(screen.getByText("http://localhost:8080")).toBeInTheDocument();
  });
});
