import { describe, it, expect } from "vitest";
import {
  cvssTooltip,
  epssTooltip,
  cvssClass,
  epssClass,
  toUtcDate,
} from "./utils";

describe("vuln/utils", () => {
  describe("cvssTooltip", () => {
    it("returns Critical for scores >= 9.0", () => {
      expect(cvssTooltip(9.0)).toBe("Critical severity");
      expect(cvssTooltip(10.0)).toBe("Critical severity");
    });
    it("returns High for scores >= 7.0 and < 9.0", () => {
      expect(cvssTooltip(7.0)).toBe("High severity");
      expect(cvssTooltip(8.9)).toBe("High severity");
    });
    it("returns Medium for scores >= 4.0 and < 7.0", () => {
      expect(cvssTooltip(4.0)).toBe("Medium severity");
      expect(cvssTooltip(6.9)).toBe("Medium severity");
    });
    it("returns Low for scores < 4.0", () => {
      expect(cvssTooltip(0.0)).toBe("Low severity");
      expect(cvssTooltip(3.9)).toBe("Low severity");
    });
  });

  describe("epssTooltip", () => {
    it("returns Very high for scores >= 0.5", () => {
      expect(epssTooltip(0.5)).toBe("Very high exploitation risk");
      expect(epssTooltip(0.9)).toBe("Very high exploitation risk");
    });
    it("returns Elevated for scores >= 0.1 and < 0.5", () => {
      expect(epssTooltip(0.1)).toBe("Elevated exploitation risk");
      expect(epssTooltip(0.49)).toBe("Elevated exploitation risk");
    });
    it("returns Moderate for scores >= 0.01 and < 0.1", () => {
      expect(epssTooltip(0.01)).toBe("Moderate exploitation risk");
      expect(epssTooltip(0.09)).toBe("Moderate exploitation risk");
    });
    it("returns Low for scores < 0.01", () => {
      expect(epssTooltip(0.001)).toBe("Low exploitation risk");
      expect(epssTooltip(0.0)).toBe("Low exploitation risk");
    });
  });

  describe("cvssClass", () => {
    it("returns muted for null scores", () => {
      expect(cvssClass(null)).toContain("text-muted-foreground");
    });
    it("returns red for scores >= 9.0", () => {
      expect(cvssClass(9.0)).toContain("text-red-700");
    });
    it("returns orange for scores >= 7.0 and < 9.0", () => {
      expect(cvssClass(7.5)).toContain("text-orange-600");
    });
    it("returns amber for scores >= 4.0 and < 7.0", () => {
      expect(cvssClass(5.0)).toContain("text-amber-600");
    });
    it("returns muted for scores < 4.0", () => {
      expect(cvssClass(3.0)).toBe("text-muted-foreground");
    });
  });

  describe("epssClass", () => {
    it("returns muted for null scores", () => {
      expect(epssClass(null)).toContain("text-muted-foreground");
    });
    it("returns red for scores >= 0.5", () => {
      expect(epssClass(0.6)).toContain("text-red-700");
    });
    it("returns orange for scores >= 0.1 and < 0.5", () => {
      expect(epssClass(0.2)).toContain("text-orange-600");
    });
    it("returns amber for scores >= 0.01 and < 0.1", () => {
      expect(epssClass(0.05)).toContain("text-amber-600");
    });
    it("returns muted for scores < 0.01", () => {
      expect(epssClass(0.005)).toBe("text-muted-foreground");
    });
  });

  describe("toUtcDate", () => {
    it("appends Z if missing", () => {
      const dt = toUtcDate("2026-03-08T12:00:00");
      expect(dt.toISOString()).toBe("2026-03-08T12:00:00.000Z");
    });
    it("does not append Z if already present", () => {
      const dt = toUtcDate("2026-03-08T12:00:00Z");
      expect(dt.toISOString()).toBe("2026-03-08T12:00:00.000Z");
    });
    it("does not append Z if timezone offset is present", () => {
      const dt = toUtcDate("2026-03-08T12:00:00+00:00");
      expect(dt.toISOString()).toBe("2026-03-08T12:00:00.000Z");
    });
  });
});
