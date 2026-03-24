import { render, screen } from "@testing-library/svelte";
import { describe, it, expect, vi, beforeEach } from "vitest";
import Page from "./+page.svelte";

// Prevent real network calls from onMount store fetch
beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    })
  );
});

describe("Settings page", () => {
  it("renders the page description", () => {
    render(Page);
    expect(
      screen.getByText(/Manage how DockGuard behaves/i)
    ).toBeInTheDocument();
  });

  it("shows loading state when settings have not yet loaded", () => {
    render(Page);
    expect(screen.getByText("Loading settings...")).toBeInTheDocument();
  });
});
