import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
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

  it("keeps only one expanded container sub-view open", async () => {
    const originalAnimate = Element.prototype.animate;
    Element.prototype.animate = vi.fn(
      () =>
        ({
          finished: Promise.resolve(),
          cancel: vi.fn(),
          play: vi.fn(),
        }) as unknown as Animation
    );

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulnerabilities: [],
        total_count: 0,
        has_more: false,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const containers = [
      {
        container_name: "alpha",
        image_name: "repo/alpha:latest",
        has_scan: true,
        scanned_at: "2024-01-01T00:00:00Z",
        total: 0,
        vulns_by_priority: {},
        vulns_by_priority_no_vex: {},
        vulns_by_severity: {},
        vulns_by_severity_no_vex: {},
        has_vex: false,
      },
      {
        container_name: "beta",
        image_name: "repo/beta:latest",
        has_scan: true,
        scanned_at: "2024-01-02T00:00:00Z",
        total: 0,
        vulns_by_priority: {},
        vulns_by_priority_no_vex: {},
        vulns_by_severity: {},
        vulns_by_severity_no_vex: {},
        has_vex: false,
      },
    ];

    try {
      const view = render(Page, { data: makeData({ containers }) });

      const alphaRow = screen.getByText("alpha").closest("tr");
      const betaRow = screen.getByText("beta").closest("tr");
      expect(alphaRow).not.toBeNull();
      expect(betaRow).not.toBeNull();

      await fireEvent.click(alphaRow!);
      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(
          expect.stringContaining("image_ref=repo%2Falpha%3Alatest")
        );
      });

      await fireEvent.click(betaRow!);
      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(
          expect.stringContaining("image_ref=repo%2Fbeta%3Alatest")
        );
      });

      await waitFor(() => {
        expect(view.container.querySelectorAll("svg.rotate-90")).toHaveLength(
          1
        );
      });
    } finally {
      Element.prototype.animate = originalAnimate;
      vi.unstubAllGlobals();
    }
  });
});
