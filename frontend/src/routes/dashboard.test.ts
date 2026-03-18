import { render, screen, waitFor } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import Page from "./+page.svelte";

// ResizeObserver is used by Chart.Container
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const emptySummary = {
  docker_connected: false,
  grype_version: null,
  db_schema: null,
  db_built: null,
  db_updating: false,
  last_db_checked_at: null,
  running_containers: null,
  images_scanned: 0,
  active_tasks: 0,
  queued_tasks: 0,
  eol_count: 0,
  urgent_count: null,
  kev_count: null,
  new_findings: null,
  vulns_by_priority: {},
  trend: [],
};

function makeData(overrides = {}) {
  return {
    summary: emptySummary,
    activities: [],
    apiError: false,
    ...overrides,
  };
}

describe("Dashboard page", () => {
  it("renders the page heading", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByRole("heading", { name: "Dashboard" })
    ).toBeInTheDocument();
  });

  it("shows Docker as disconnected when docker_connected is false", () => {
    render(Page, { data: makeData() });
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("shows Docker as connected when docker_connected is true", () => {
    render(Page, {
      data: makeData({ summary: { ...emptySummary, docker_connected: true } }),
    });
    expect(screen.getByText("Connected")).toBeInTheDocument();
  });

  it("shows API error banner when apiError is true", () => {
    render(Page, { data: makeData({ apiError: true }) });
    expect(screen.getByText("Unexpected Error")).toBeInTheDocument();
  });

  it("shows empty activity state when no activities", async () => {
    render(Page, { data: makeData() });
    await waitFor(() =>
      expect(screen.getByText("No scans have run yet.")).toBeInTheDocument()
    );
  });

  it("shows no-trend placeholder when trend data is empty", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByText("No scan data yet — trend will appear here.")
    ).toBeInTheDocument();
  });

  it("shows grype version when provided", () => {
    render(Page, {
      data: makeData({ summary: { ...emptySummary, grype_version: "0.99.0" } }),
    });
    expect(screen.getByText("0.99.0")).toBeInTheDocument();
  });
});
