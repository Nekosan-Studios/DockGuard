import { describe, it, expect } from "vitest";
import { cn } from "./utils";

describe("utils: cn", () => {
  it("merges tailwind classes correctly", () => {
    expect(cn("bg-red-500", "text-white")).toBe("bg-red-500 text-white");
  });

  it("resolves tailwind conflicts correctly using twMerge", () => {
    // padding x-4 should be overridden by px-6
    expect(cn("px-4 py-2", "px-6")).toBe("py-2 px-6");
  });

  it("handles conditional classes using clsx", () => {
    const isError = true;
    expect(
      cn("btn", isError && "bg-red-500 text-white", !isError && "bg-green-500")
    ).toBe("btn bg-red-500 text-white");
  });
});
