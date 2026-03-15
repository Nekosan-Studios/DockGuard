import { describe, it, expect } from "vitest";
import {
  cvssTooltip,
  epssTooltip,
  cvssClass,
  epssClass,
  toUtcDate,
  priorityFromRiskScore,
  priorityTooltip,
  decodeCvssVector,
  referenceBaseText,
  referenceDisplayText,
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

  describe("priorityFromRiskScore", () => {
    it("returns Urgent for risk score >= 80", () => {
      expect(priorityFromRiskScore(80.0)).toBe("Urgent");
      expect(priorityFromRiskScore(100.0)).toBe("Urgent");
    });
    it("returns High for risk score >= 50 and < 80", () => {
      expect(priorityFromRiskScore(50.0)).toBe("High");
      expect(priorityFromRiskScore(79.9)).toBe("High");
    });
    it("returns Medium for risk score >= 20 and < 50", () => {
      expect(priorityFromRiskScore(20.0)).toBe("Medium");
      expect(priorityFromRiskScore(49.9)).toBe("Medium");
    });
    it("returns Low for risk score < 20", () => {
      expect(priorityFromRiskScore(0.0)).toBe("Low");
      expect(priorityFromRiskScore(19.9)).toBe("Low");
    });
    it("returns Low for null risk score", () => {
      expect(priorityFromRiskScore(null)).toBe("Low");
    });
  });

  describe("priorityTooltip", () => {
    it("includes priority label and score", () => {
      expect(priorityTooltip(85.0)).toBe(
        "Urgent priority — Grype Risk Score: 85.0/100"
      );
    });
    it("handles null risk score", () => {
      expect(priorityTooltip(null)).toBe(
        "Low priority — Grype Risk Score: —/100"
      );
    });
  });

  describe("decodeCvssVector", () => {
    it("decodes a valid CVSS 3.1 vector", () => {
      const result = decodeCvssVector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      );
      expect(result).not.toBeNull();
      expect(result!.map((c) => ({ label: c.label, value: c.value }))).toEqual([
        { label: "Attack Vector", value: "Network" },
        { label: "Attack Complexity", value: "Low" },
        { label: "Privileges Required", value: "None" },
        { label: "User Interaction", value: "None" },
        { label: "Scope", value: "Unchanged" },
        { label: "Confidentiality", value: "High" },
        { label: "Integrity", value: "High" },
        { label: "Availability", value: "High" },
      ]);
      // Each component should have description and severity
      for (const c of result!) {
        expect(c).toHaveProperty("description");
        expect(c).toHaveProperty("severity");
        expect(["none", "low", "medium", "high"]).toContain(c.severity);
      }
    });

    it("returns null when AV metric is missing", () => {
      expect(decodeCvssVector("AC:L/PR:N")).toBeNull();
    });

    it("preserves raw values for unknown metric codes", () => {
      const result = decodeCvssVector(
        "CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H"
      );
      expect(result).not.toBeNull();
      expect(result![1].label).toBe("Attack Complexity");
      expect(result![1].value).toBe("X");
    });

    it("decodes a CVSS 4.0 vector", () => {
      const result = decodeCvssVector(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
      );
      expect(result).not.toBeNull();
      expect(result!.length).toBe(11);
      expect(result!.map((c) => c.label)).toContain("Attack Requirements");
      expect(result!.map((c) => c.label)).toContain("Vuln. Availability");
      expect(result!.map((c) => c.label)).toContain("Sub. Availability");
      const va = result!.find((c) => c.label === "Vuln. Availability");
      expect(va!.value).toBe("High");
      expect(va!.severity).toBe("high");
    });
  });

  describe("referenceBaseText", () => {
    it("formats mapped NVD links with CVE", () => {
      expect(
        referenceBaseText("https://nvd.nist.gov/vuln/detail/CVE-2026-12345")
      ).toBe("NVD • CVE-2026-12345");
    });

    it("falls back to extracted global ID when host is unmapped", () => {
      expect(
        referenceBaseText("https://vendor.example/advisories/CVE-2025-9999")
      ).toBe("CVE-2025-9999");
    });

    it("falls back to hostname when no known ID exists", () => {
      expect(referenceBaseText("https://example.com/security/advisory")).toBe(
        "example.com"
      );
    });
  });

  describe("referenceDisplayText", () => {
    it("appends cached title when present", () => {
      expect(
        referenceDisplayText(
          "https://github.com/advisories/GHSA-abcd-1234-efgh",
          "GitHub advisory title"
        )
      ).toBe("GitHub Advisory • GHSA-ABCD-1234-EFGH: GitHub advisory title");
    });

    it("returns base text when title missing", () => {
      expect(
        referenceDisplayText(
          "https://security-tracker.debian.org/tracker/CVE-2024-1111",
          null
        )
      ).toBe("Debian Tracker • CVE-2024-1111");
    });
  });
});
