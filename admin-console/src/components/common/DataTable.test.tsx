// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DataTable, type Column } from "./DataTable";

interface TestRow {
  id: string;
  name: string;
  score: number;
}

const columns: Column<TestRow>[] = [
  { key: "id", header: "ID", render: (r) => r.id },
  { key: "name", header: "Name", render: (r) => r.name },
  { key: "score", header: "Score", render: (r) => String(r.score) },
];

const data: TestRow[] = [
  { id: "1", name: "Alice", score: 95 },
  { id: "2", name: "Bob", score: 87 },
];

describe("DataTable", () => {
  it("renders column headers", () => {
    render(<DataTable columns={columns} data={data} keyFn={(r) => r.id} />);
    expect(screen.getByText("ID")).toBeInTheDocument();
    expect(screen.getByText("Name")).toBeInTheDocument();
    expect(screen.getByText("Score")).toBeInTheDocument();
  });

  it("renders row data", () => {
    render(<DataTable columns={columns} data={data} keyFn={(r) => r.id} />);
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("Bob")).toBeInTheDocument();
    expect(screen.getByText("95")).toBeInTheDocument();
  });

  it("renders empty message when no rows", () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        keyFn={(r) => r.id}
        emptyMessage="Nothing here"
      />,
    );
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("renders default empty message", () => {
    render(<DataTable columns={columns} data={[]} keyFn={(r) => r.id} />);
    expect(screen.getByText("No data")).toBeInTheDocument();
  });

  it("renders correct number of rows", () => {
    const { container } = render(
      <DataTable columns={columns} data={data} keyFn={(r) => r.id} />,
    );
    const tbody = container.querySelector("tbody");
    expect(tbody?.children.length).toBe(2);
  });

  it("applies column width when specified", () => {
    const cols: Column<TestRow>[] = [
      { key: "id", header: "ID", render: (r) => r.id, width: "100px" },
    ];
    const { container } = render(
      <DataTable columns={cols} data={data} keyFn={(r) => r.id} />,
    );
    const th = container.querySelector("th");
    expect(th?.style.width).toBe("100px");
  });
});
