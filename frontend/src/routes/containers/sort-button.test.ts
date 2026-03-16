import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import SortButton from "./sort-button.svelte";

describe("SortButton", () => {
  it("renders the label text", () => {
    render(SortButton, { label: "Name" });
    expect(screen.getByText("Name")).toBeInTheDocument();
  });

  it("renders neutral icon when sortDirection is false", () => {
    const { container } = render(SortButton, {
      label: "Name",
      sortDirection: false,
    });
    // ArrowUpDown icon has opacity-40 class; the others do not
    const svg = container.querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.getAttribute("class")).toContain("opacity-40");
  });

  it("renders up arrow when sortDirection is asc", () => {
    const { container } = render(SortButton, {
      label: "Name",
      sortDirection: "asc",
    });
    const svg = container.querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.getAttribute("class")).not.toContain("opacity-40");
  });

  it("renders down arrow when sortDirection is desc", () => {
    const { container } = render(SortButton, {
      label: "Name",
      sortDirection: "desc",
    });
    const svg = container.querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.getAttribute("class")).not.toContain("opacity-40");
  });
});
