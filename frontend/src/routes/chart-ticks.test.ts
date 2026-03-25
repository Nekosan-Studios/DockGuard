/**
 * Tests for x-axis tick behaviour in the 30-Day Trend chart.
 *
 * Root cause documented here: layerchart's autoTickVals() has two branches:
 *   - Band scale (string domain): only the explicit `ticks` prop is honoured;
 *     the `count` derived from `tickSpacing` is silently ignored → all labels
 *     are always rendered regardless of chart width.
 *   - Time scale (Date domain): `count` IS used via scale.ticks(count), so
 *     `tickSpacing` works, BUT D3 can generate sub-day ticks for sparse data
 *     (e.g. 5 days wide-chart → "Mar 21 Mar 21 Mar 22 Mar 22 ...").
 *
 * Fix: compute ticks explicitly from the actual data-point dates, subsampled
 * to fit the chart width.  This guarantees:
 *   1. No sub-day interpolation → no repeated date labels.
 *   2. Labels don't overlap on narrow screens.
 */
import { describe, it, expect } from "vitest";
import { scaleBand, scaleTime } from "d3-scale";
import { autoTickVals } from "layerchart/utils/ticks";

// ---------------------------------------------------------------------------
// Helpers that mirror the logic in +page.svelte
// ---------------------------------------------------------------------------

function makeDates(count: number, startIso = "2026-02-24"): Date[] {
  return Array.from({ length: count }, (_, i) => {
    const d = new Date(startIso);
    d.setDate(d.getDate() + i);
    return d;
  });
}

/**
 * The xTicks computation from +page.svelte — exported here for unit testing.
 * Returns a subsampled array of the actual data-point dates that fits within
 * the given chartWidth (60 px per label, minimum 3 ticks).
 */
export function computeXTicks(dates: Date[], chartWidth: number): Date[] {
  const maxTicks =
    chartWidth > 0 ? Math.max(3, Math.round(chartWidth / 60)) : dates.length;
  if (dates.length <= maxTicks) return dates;
  const step = Math.ceil(dates.length / maxTicks);
  return dates.filter((_, i) => i % step === 0);
}

// ---------------------------------------------------------------------------
// Demonstrating the original band-scale bug (string x values)
// ---------------------------------------------------------------------------

describe("autoTickVals — band scale (string x values, old approach)", () => {
  const STRING_DOMAIN = makeDates(30).map(
    (d) => `${d.toLocaleString("en", { month: "short" })} ${d.getDate()}`
  );

  it("returns all 30 domain values regardless of count", () => {
    const scale = scaleBand().domain(STRING_DOMAIN);
    expect(autoTickVals(scale, undefined, 5)).toHaveLength(30);
    expect(autoTickVals(scale, undefined, 3)).toHaveLength(30);
    expect(autoTickVals(scale, undefined, 10)).toHaveLength(30);
  });
});

// ---------------------------------------------------------------------------
// Demonstrating the sub-day interpolation bug (time scale + tickSpacing)
// ---------------------------------------------------------------------------

describe("autoTickVals — time scale with tickSpacing (intermediate approach)", () => {
  it("generates sub-day ticks for sparse data, causing repeated date labels", () => {
    const dates = makeDates(5); // only 5 data points
    const scale = scaleTime().domain([dates[0], dates[dates.length - 1]]);

    // tickSpacing=60 on a 1200px chart → count=20
    // D3 picks a sub-day interval to fit ~20 ticks in 5 days
    const ticks = autoTickVals(scale, undefined, 20);

    // More ticks than data points → sub-day ticks → repeated "MMM d" labels
    expect(ticks.length).toBeGreaterThan(5);
    // Multiple ticks fall on the same calendar day
    const days = new Set(ticks.map((t: Date) => t.toDateString()));
    expect(days.size).toBeLessThan(ticks.length);
  });
});

// ---------------------------------------------------------------------------
// The fix: computeXTicks — ticks from actual data points, width-capped
// ---------------------------------------------------------------------------

describe("computeXTicks (current approach)", () => {
  it("returns all dates when they fit within the available width", () => {
    const dates = makeDates(5);
    // 5 dates × 60px = 300px needed; 600px available → all fit
    expect(computeXTicks(dates, 600)).toHaveLength(5);
    expect(computeXTicks(dates, 300)).toHaveLength(5);
  });

  it("never produces more ticks than actual data points", () => {
    const dates = makeDates(5);
    // Very wide chart — should still not invent extra ticks
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
