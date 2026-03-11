import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import ModeToggle from "./mode-toggle.svelte";

describe("mode-toggle", () => {
  it("renders a button with a screen reader text", () => {
    render(ModeToggle);

    const button = screen.getByRole("button");
    expect(button).toBeInTheDocument();

    // The span text is sr-only
    const text = screen.getByText("Toggle theme");
    expect(text).toBeInTheDocument();
    expect(text.className).toBe("sr-only");
  });
});
