import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/svelte";
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

  it("renders CVSS vector component labels in tooltip when cvssVector is provided", async () => {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    const { container } = render(PriorityCellTestWrapper, {
      riskScore: 85.0,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    });
    const trigger = container.querySelector("button");
    if (trigger) fireEvent.pointerEnter(trigger);
    expect(await screen.findByText("Attack Vector")).toBeInTheDocument();
    expect(await screen.findByText("Network")).toBeInTheDocument();
  });

  it("does not render CVSS vector section in tooltip when cvssVector is null", async () => {
    const { container } = render(PriorityCellTestWrapper, {
      riskScore: 85.0,
      cvssVector: null,
    });
    const trigger = container.querySelector("button");
    if (trigger) fireEvent.pointerEnter(trigger);
    // Tooltip opens but no vector labels
    await screen.findByText(/Urgent/i);
    expect(screen.queryByText("Attack Vector")).not.toBeInTheDocument();
  });

  it("does not render CVSS vector section when vector string is malformed", async () => {
    const { container } = render(PriorityCellTestWrapper, {
      riskScore: 85.0,
      cvssVector: "not-a-valid-vector",
    });
    const trigger = container.querySelector("button");
    if (trigger) fireEvent.pointerEnter(trigger);
    await screen.findByText(/Urgent/i);
    expect(screen.queryByText("Attack Vector")).not.toBeInTheDocument();
  });
});
