import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import PriorityCellTestWrapper from "./PriorityCellTestWrapper.svelte";

globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

describe("PriorityCell", () => {
  it("renders Urgent for risk score >= 80", () => {
    render(PriorityCellTestWrapper, { riskScore: 85.0 });

    const badge = screen.getByText("Urgent");
    expect(badge).toBeInTheDocument();
    expect(badge.parentElement?.className).toContain("bg-red-100");
  });

  it("renders High for risk score >= 50 and < 80", () => {
    render(PriorityCellTestWrapper, { riskScore: 60.0 });

    const badge = screen.getByText("High");
    expect(badge).toBeInTheDocument();
    expect(badge.parentElement?.className).toContain("bg-orange-100");
  });

  it("renders Medium for risk score >= 20 and < 50", () => {
    render(PriorityCellTestWrapper, { riskScore: 30.0 });

    const badge = screen.getByText("Medium");
    expect(badge).toBeInTheDocument();
    expect(badge.parentElement?.className).toContain("bg-amber-100");
  });

  it("renders Low for risk score < 20", () => {
    render(PriorityCellTestWrapper, { riskScore: 5.0 });

    const badge = screen.getByText("Low");
    expect(badge).toBeInTheDocument();
    expect(badge.parentElement?.className).toContain("bg-blue-100");
  });

  it("renders Low for null risk score", () => {
    render(PriorityCellTestWrapper, { riskScore: null });

    const badge = screen.getByText("Low");
    expect(badge).toBeInTheDocument();
  });

  it("shows the numeric risk score as sub-label", () => {
    render(PriorityCellTestWrapper, { riskScore: 85.0 });

    expect(screen.getByText("85.0")).toBeInTheDocument();
  });
});
