import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusCard } from "./StatusCard";

describe("StatusCard", () => {
  it("renders title and string value", () => {
    render(<StatusCard title="Server" value="ok" />);
    expect(screen.getByText("Server")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
  });

  it("renders numeric value", () => {
    render(<StatusCard title="Count" value={42} />);
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("renders subtitle when provided", () => {
    render(<StatusCard title="Status" value="ok" subtitle="v4.0.0" />);
    expect(screen.getByText("v4.0.0")).toBeInTheDocument();
  });

  it("omits subtitle when not provided", () => {
    const { container } = render(
      <StatusCard title="Status" value="ok" />,
    );
    expect(
      container.querySelector(".status-card__subtitle"),
    ).toBeNull();
  });

  it("applies default variant class", () => {
    const { container } = render(
      <StatusCard title="Status" value="ok" />,
    );
    expect(container.firstChild).toHaveClass("status-card--default");
  });

  it("applies success variant class", () => {
    const { container } = render(
      <StatusCard title="Status" value="ok" variant="success" />,
    );
    expect(container.firstChild).toHaveClass("status-card--success");
  });

  it("applies danger variant class", () => {
    const { container } = render(
      <StatusCard title="Errors" value={5} variant="danger" />,
    );
    expect(container.firstChild).toHaveClass("status-card--danger");
  });
});
