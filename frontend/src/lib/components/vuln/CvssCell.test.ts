import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import CvssCell from "./CvssCell.svelte";

describe("CvssCell", () => {
  it("renders a dash when score is null", () => {
    const { container } = render(CvssCell, { score: null });
    expect(container).toHaveTextContent("—");
  });

  it("renders a formatted score and applies the correct class for high scores", () => {
    const { container } = render(CvssCell, { score: 8.5 });

    // Tooltip triggers show the exact text
    const cellText = screen.getByText("8.5");
    expect(cellText).toBeInTheDocument();

    // The parent cell should have the orange class from cvssClass(8.5)
    const cellNode = container.querySelector("td");
    expect(cellNode?.className).toContain("text-orange-600");
  });

  it("formats integers to one decimal place", () => {
    render(CvssCell, { score: 9 });
    expect(screen.getByText("9.0")).toBeInTheDocument();
  });
});
