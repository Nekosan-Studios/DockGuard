import { render, screen } from "@testing-library/svelte";
import { describe, it, expect, vi } from "vitest";
import Page from "./+page.svelte";

vi.mock("$app/stores", async () => {
  const { readable } = await import("svelte/store");
  return {
    page: readable({
      url: new URL("http://localhost/containers"),
      params: {},
      route: { id: "/containers" },
      status: 200,
      error: null,
      data: {},
      form: undefined,
      state: {},
    }),
  };
});

vi.mock("$app/navigation", () => ({
  replaceState: vi.fn(),
  goto: vi.fn(),
}));

function makeData(overrides = {}) {
  return {
    containers: [],
    apiError: false,
    ...overrides,
  };
}

describe("Containers page", () => {
  it("renders the page heading", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByRole("heading", { name: "Containers" })
    ).toBeInTheDocument();
  });

  it("shows empty state when there are no containers", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByText("No running containers found.")
    ).toBeInTheDocument();
  });

  it("shows API error content when apiError is true", () => {
    render(Page, { data: makeData({ apiError: true }) });
    expect(screen.getByText("Unexpected Error")).toBeInTheDocument();
  });

  it("renders column headers when containers are present", () => {
    const container = {
      container_name: "my-app",
      image_name: "nginx:latest",
      scanned_at: "2024-01-01T00:00:00Z",
      vulns_by_priority: {},
      vulns_by_priority_no_vex: {},
      has_vex: false,
      vulnerabilities: [],
    };
    render(Page, { data: makeData({ containers: [container] }) });
    expect(screen.getByText("Container")).toBeInTheDocument();
    expect(screen.getByText("Vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText("Last Scanned")).toBeInTheDocument();
  });
});
