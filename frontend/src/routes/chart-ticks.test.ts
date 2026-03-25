/**
 * Tests for x-axis tick behaviour in the 30-Day Trend chart.
 *
 * Problem: layerchart's time scale generates sub-day ticks to fill available
 * space when data is sparse (e.g. 5 days on a wide chart → "Mar 21 Mar 21
 * Mar 22 Mar 22 ..."). tickSpacing cannot prevent this because it only controls
 * count, not the minimum tick granularity.
 *
 * Fix (computeXTicks): compute ticks explicitly from the actual data-point
 * dates, subsampled to fit the chart width. This guarantees:
 *   1. No sub-day interpolation → no repeated date labels.
 *   2. Labels don't overlap on narrow screens.
 */
import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// computeXTicks — mirrors the logic in +page.svelte exactly
// ---------------------------------------------------------------------------

export function computeXTicks(dates: Date[], chartWidth: number): Date[] {
  const maxTicks =
    chartWidth > 0 ? Math.max(3, Math.round(chartWidth / 60)) : dates.length;
  if (dates.length <= maxTicks) return dates;
  const step = Math.ceil(dates.length / maxTicks);
  return dates.filter((_, i) => i % step === 0);
}

function makeDates(count: number, startIso = "2026-02-24"): Date[] {
  return Array.from({ length: count }, (_, i) => {
    const d = new Date(startIso);
    d.setDate(d.getDate() + i);
    return d;
  });
}

// ---------------------------------------------------------------------------

describe("computeXTicks", () => {
  it("returns all dates when they fit within the available width", () => {
    const dates = makeDates(5);
    expect(computeXTicks(dates, 600)).toHaveLength(5);
    expect(computeXTicks(dates, 300)).toHaveLength(5);
  });

  it("never produces more ticks than actual data points", () => {
    const dates = makeDates(5);
    // Wide chart should not invent extra ticks between data points
    expect(computeXTicks(dates, 2000)).toHaveLength(5);
  });

  it("subsamples when 30 data points don't fit in a narrow chart", () => {
    const dates = makeDates(30);
    const ticks = computeXTicks(dates, 300); // max ~5 ticks
    expect(ticks.length).toBeLessThanOrEqual(6);
    expect(ticks.length).toBeGreaterThanOrEqual(3);
  });

  it("all returned ticks are from the original data-point dates (no interpolation)", () => {
    const dates = makeDates(30);
    const dateSet = new Set(dates.map((d) => d.toISOString()));
    const ticks = computeXTicks(dates, 300);
    for (const t of ticks) {
      expect(dateSet.has(t.toISOString())).toBe(true);
    }
  });

  it("returns more ticks on wider charts", () => {
    const dates = makeDates(30);
    const narrow = computeXTicks(dates, 300);
    const wide = computeXTicks(dates, 1200);
    expect(wide.length).toBeGreaterThan(narrow.length);
  });

  it("returns at least 3 ticks even on very narrow charts", () => {
    const dates = makeDates(30);
    expect(computeXTicks(dates, 50).length).toBeGreaterThanOrEqual(3);
  });

  it("handles chartWidth=0 (pre-mount) by returning all dates", () => {
    const dates = makeDates(10);
    expect(computeXTicks(dates, 0)).toHaveLength(10);
  });
});
