import { render, screen } from "@testing-library/svelte";
import { describe, it, expect, vi } from "vitest";
import Page from "./+page.svelte";

vi.mock("$app/stores", async () => {
  const { readable } = await import("svelte/store");
  return {
    page: readable({
      url: new URL("http://localhost/vulnerabilities"),
      params: {},
      route: { id: "/vulnerabilities" },
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

// IntersectionObserver is used by the infinite scroll sentinel
globalThis.IntersectionObserver = class IntersectionObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
  constructor() {}
  takeRecords() {
    return [];
  }
} as unknown as typeof IntersectionObserver;

function makeData(overrides = {}) {
  return {
    report: "urgent",
    sort_by: "severity",
    sort_dir: "asc",
    vulnerabilities: [],
    count: 0,
    total_count: 0,
    total_instances: 0,
    has_more: false,
    apiError: false,
    eol_images: [],
    has_any_vex: false,
    ...overrides,
  };
}

describe("Vulnerabilities page", () => {
  it("renders the page heading", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByRole("heading", { name: "Vulnerabilities" })
    ).toBeInTheDocument();
  });

  it("shows empty state when there are no vulnerabilities", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByText("No vulnerabilities found for this report.")
    ).toBeInTheDocument();
  });

  it("shows API error content when apiError is true", () => {
    render(Page, { data: makeData({ apiError: true }) });
    expect(screen.getByText("Unexpected Error")).toBeInTheDocument();
  });

  it("shows EOL warning banner when eol_images are present", () => {
    render(Page, {
      data: makeData({
        eol_images: [{ container_name: "myapp", distro: "Ubuntu 18.04" }],
      }),
    });
    expect(
      screen.getByText("End-of-Life Systems Detected")
    ).toBeInTheDocument();
  });

  it("shows Report dropdown", () => {
    render(Page, { data: makeData() });
    expect(screen.getByText("Report:")).toBeInTheDocument();
  });
});
