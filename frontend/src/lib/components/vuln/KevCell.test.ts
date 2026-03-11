import { render } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import KevCell from "./KevCell.svelte";

describe("KevCell", () => {
  it("renders a dash when isKev is false", () => {
    const { container } = render(KevCell, { isKev: false });
    expect(container).toHaveTextContent("—");
  });

  it("renders an icon and tooltip trigger when isKev is true", () => {
    const { container } = render(KevCell, { isKev: true });

    // The text shouldn't be the dash anymore
    expect(container).not.toHaveTextContent("—");

    // Finds the inner SVG icon container from Lucide CircleCheck
    const svg = container.querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.className.baseVal).toContain("text-red-600");
  });
});
