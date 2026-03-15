// Advisory enrichment types & logic for VulnDetailModal
// Supports NVD API 2.0 (CVE-*) and GitHub Advisory API (GHSA-*)

// ─── Types ──────────────────────────────────────────────────────────────────

export type NvdCvssMetric = {
  source: string;
  type: string;
  cvssData: {
    version: string;
    baseScore: number;
    baseSeverity: string;
    vectorString: string;
  };
};

export type NvdCveData = {
  cve: {
    id: string;
    sourceIdentifier: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    cveTags?: Array<{ sourceIdentifier: string; tags: string[] }>;
    metrics: {
      cvssMetricV40?: NvdCvssMetric[];
      cvssMetricV31?: NvdCvssMetric[];
      cvssMetricV30?: NvdCvssMetric[];
      cvssMetricV2?: NvdCvssMetric[];
    };
    cisaExploitAdd?: string;
    cisaActionDue?: string;
    cisaRequiredAction?: string;
    cisaVulnerabilityName?: string;
  };
};

export type GhsaVulnerability = {
  package: { ecosystem: string; name: string };
  vulnerable_version_range: string | null;
  first_patched_version: string | null;
  vulnerable_functions: string[];
};

export type GhsaCredit = {
  user: { login: string; html_url: string };
  type: string;
};

export type GhsaData = {
  ghsa_id: string;
  cve_id: string | null;
  html_url: string;
  summary: string;
  description: string | null;
  type: string;
  severity: string;
  published_at: string;
  updated_at: string;
  github_reviewed_at: string | null;
  nvd_published_at: string | null;
  withdrawn_at: string | null;
  vulnerabilities: GhsaVulnerability[];
  cvss: { vector_string: string | null; score: number | null } | null;
  cvss_severities: {
    cvss_v3: { vector_string: string | null; score: number | null } | null;
    cvss_v4: { vector_string: string | null; score: number | null } | null;
  } | null;
  credits: GhsaCredit[];
};

export type EnrichedData =
  | { source: "nvd"; data: NvdCveData }
  | { source: "ghsa"; data: GhsaData };

export type CvssRow = {
  version: string;
  type: string;
  source: string;
  score: number;
  severity: string;
};

// ─── Helpers ────────────────────────────────────────────────────────────────

export function enrichmentSource(id: string): "nvd" | "ghsa" | null {
  if (id.startsWith("CVE-")) return "nvd";
  if (id.startsWith("GHSA-")) return "ghsa";
  return null;
}

export async function fetchEnrichment(
  id: string,
  source: "nvd" | "ghsa",
  signal: AbortSignal
): Promise<EnrichedData | null> {
  let res: Response;
  if (source === "nvd") {
    res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`,
      { signal }
    );
  } else {
    res = await fetch(
      `https://api.github.com/advisories/${encodeURIComponent(id)}`,
      {
        headers: { Accept: "application/vnd.github+json" },
        signal,
      }
    );
  }

  if (!res.ok) return null;

  const json = (await res.json()) as Record<string, unknown>;
  if (source === "nvd") {
    const cveItems = json?.vulnerabilities as NvdCveData[] | undefined;
    if (!cveItems || cveItems.length === 0) return null;
    return { source: "nvd", data: cveItems[0] };
  }
  return { source: "ghsa", data: json as unknown as GhsaData };
}

export function formatShortDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function nvdStatusClass(status: string): string {
  if (status === "Analyzed")
    return "border-emerald-200 bg-emerald-100 text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300";
  if (status === "Rejected")
    return "border-red-200 bg-red-100 text-red-700 dark:border-red-700 dark:bg-red-900/40 dark:text-red-300";
  if (["Awaiting Analysis", "Undergoing Analysis", "Modified"].includes(status))
    return "border-amber-200 bg-amber-100 text-amber-700 dark:border-amber-700 dark:bg-amber-900/40 dark:text-amber-300";
  return "border-slate-200 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300";
}

export function nvdCvssRows(data: NvdCveData): CvssRow[] {
  const rows: CvssRow[] = [];
  const { metrics } = data.cve;
  for (const m of metrics.cvssMetricV40 ?? [])
    rows.push({
      version: "4.0",
      type: m.type,
      source: m.source,
      score: m.cvssData.baseScore,
      severity: m.cvssData.baseSeverity,
    });
  for (const m of metrics.cvssMetricV31 ?? [])
    rows.push({
      version: "3.1",
      type: m.type,
      source: m.source,
      score: m.cvssData.baseScore,
      severity: m.cvssData.baseSeverity,
    });
  for (const m of metrics.cvssMetricV30 ?? [])
    rows.push({
      version: "3.0",
      type: m.type,
      source: m.source,
      score: m.cvssData.baseScore,
      severity: m.cvssData.baseSeverity,
    });
  for (const m of metrics.cvssMetricV2 ?? [])
    rows.push({
      version: "2.0",
      type: m.type,
      source: m.source,
      score: m.cvssData.baseScore,
      severity: m.cvssData.baseSeverity,
    });
  return rows;
}

export function ghsaCvssRows(data: GhsaData): CvssRow[] {
  const rows: CvssRow[] = [];
  const v3 = data.cvss_severities?.cvss_v3;
  const v4 = data.cvss_severities?.cvss_v4;
  if (v4?.score != null)
    rows.push({
      version: "4.0",
      type: "Primary",
      source: "GitHub/CNA",
      score: v4.score,
      severity: data.severity.toUpperCase(),
    });
  if (v3?.score != null)
    rows.push({
      version: "3.1",
      type: "Primary",
      source: "GitHub/CNA",
      score: v3.score,
      severity: data.severity.toUpperCase(),
    });
  if (rows.length === 0 && data.cvss?.score != null)
    rows.push({
      version: "3.x",
      type: "Primary",
      source: "GitHub/CNA",
      score: data.cvss.score,
      severity: data.severity.toUpperCase(),
    });
  return rows;
}

export function creditTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    analyst: "analyst",
    finder: "finder",
    reporter: "reporter",
    coordinator: "coordinator",
    remediation_developer: "remediation developer",
    remediation_reviewer: "remediation reviewer",
    remediation_verifier: "remediation verifier",
    tool: "tool",
    sponsor: "sponsor",
    other: "other",
  };
  return labels[type] ?? type;
}
