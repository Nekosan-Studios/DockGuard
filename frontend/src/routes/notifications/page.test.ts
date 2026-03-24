import { render, screen } from "@testing-library/svelte";
import { describe, it, expect, vi, beforeEach } from "vitest";
import Page from "./+page.svelte";

// Prevent real network calls from onMount store fetches
beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [],
    })
  );
});

describe("Notifications page", () => {
  it("renders the page description", () => {
    render(Page);
    expect(
      screen.getByText(/Configure notification channels/i)
    ).toBeInTheDocument();
  });

  it("shows loading state on initial render", () => {
    render(Page);
    expect(screen.getByText("Loading...")).toBeInTheDocument();
  });
});
