export const SEVERITY_CLASSES: Record<string, string> = {
  Critical:
    "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800",
  High: "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800",
  Medium:
    "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-800",
  Low: "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800",
  Negligible:
    "bg-gray-100 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600",
  Unknown:
    "bg-gray-100 text-gray-500 border-gray-300 dark:bg-gray-800 dark:text-gray-500 dark:border-gray-600",
};

export function toUtcDate(iso: string): Date {
  return new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
}

export function cvssTooltip(score: number): string {
  if (score >= 9.0) return "Critical severity";
  if (score >= 7.0) return "High severity";
  if (score >= 4.0) return "Medium severity";
  return "Low severity";
}

export function epssTooltip(score: number): string {
  if (score >= 0.5) return "Very high exploitation risk";
  if (score >= 0.1) return "Elevated exploitation risk";
  if (score >= 0.01) return "Moderate exploitation risk";
  return "Low exploitation risk";
}

export function cvssClass(score: number | null): string {
  if (score === null) return "text-muted-foreground";
  if (score >= 9.0) return "font-bold text-red-700 dark:text-red-400";
  if (score >= 7.0) return "font-semibold text-orange-600 dark:text-orange-400";
  if (score >= 4.0) return "text-amber-600 dark:text-amber-400";
  return "text-muted-foreground";
}

export function riskScoreTooltip(score: number): string {
  return `Grype Risk Score: ${score.toFixed(1)} / 100 — composite of CVSS, EPSS, and KEV`;
}

export function epssClass(score: number | null): string {
  if (score === null) return "text-muted-foreground";
  if (score >= 0.5) return "font-bold text-red-700 dark:text-red-400";
  if (score >= 0.1) return "font-semibold text-orange-600 dark:text-orange-400";
  if (score >= 0.01) return "text-amber-600 dark:text-amber-400";
  return "text-muted-foreground";
}

// ── Priority system (risk-score-based) ──────────────────────────────────────

export const PRIORITY_ORDER = ["Urgent", "High", "Medium", "Low"] as const;
export type Priority = (typeof PRIORITY_ORDER)[number];

export const PRIORITY_CLASSES: Record<string, string> = {
  Urgent:
    "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800",
  High: "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800",
  Medium:
    "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-800",
  Low: "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800",
};

export function priorityFromRiskScore(riskScore: number | null): Priority {
  if (riskScore == null) return "Low";
  if (riskScore >= 80) return "Urgent";
  if (riskScore >= 50) return "High";
  if (riskScore >= 20) return "Medium";
  return "Low";
}

export function priorityTooltip(riskScore: number | null): string {
  const priority = priorityFromRiskScore(riskScore);
  const score = riskScore != null ? riskScore.toFixed(1) : "—";
  return `${priority} priority — Grype Risk Score: ${score}/100`;
}

// ── CVSS vector decoding ────────────────────────────────────────────────────

export interface VectorComponent {
  label: string;
  value: string;
}

const AV_LABELS: Record<string, string> = {
  N: "Network",
  A: "Adjacent",
  L: "Local",
  P: "Physical",
};
const AC_LABELS: Record<string, string> = { L: "Low", H: "High" };
const PR_LABELS: Record<string, string> = { N: "None", L: "Low", H: "High" };
const UI_LABELS: Record<string, string> = { N: "None", R: "Required" };
const S_LABELS: Record<string, string> = { U: "Unchanged", C: "Changed" };
const CIA_LABELS: Record<string, string> = {
  N: "None",
  L: "Low",
  H: "High",
};

/** Decode a CVSS v3.x vector string into labeled components. */
export function decodeCvssVector(vector: string): VectorComponent[] | null {
  const raw = vector.replace(/^CVSS:\d+\.\d+\//, "");
  const parts = raw.split("/");
  const map: Record<string, string> = {};
  for (const part of parts) {
    const [k, v] = part.split(":");
    if (k && v) map[k] = v;
  }
  if (!map["AV"]) return null;
  return [
    { label: "Attack Vector", value: AV_LABELS[map["AV"]] ?? map["AV"] },
    { label: "Attack Complexity", value: AC_LABELS[map["AC"]] ?? map["AC"] },
    {
      label: "Privileges Required",
      value: PR_LABELS[map["PR"]] ?? map["PR"],
    },
    { label: "User Interaction", value: UI_LABELS[map["UI"]] ?? map["UI"] },
    { label: "Scope", value: S_LABELS[map["S"]] ?? map["S"] },
    { label: "Confidentiality", value: CIA_LABELS[map["C"]] ?? map["C"] },
    { label: "Integrity", value: CIA_LABELS[map["I"]] ?? map["I"] },
    { label: "Availability", value: CIA_LABELS[map["A"]] ?? map["A"] },
  ];
}

const GLOBAL_REFERENCE_ID_PATTERNS = [
  /CVE-\d{4}-\d{4,}/i,
  /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i,
  /RHSA-\d{4}:\d+/i,
  /USN-\d{4,}-\d+/i,
  /ALAS\d*-\d{4}-\d+/i,
  /ALAS-\d{4}-\d+/i,
];

interface ReferenceRule {
  label: string;
  host: RegExp;
  path: RegExp;
  idPatterns?: RegExp[];
  customId?: (url: URL) => string | null;
}

const REFERENCE_RULES: ReferenceRule[] = [
  {
    label: "NVD",
    host: /^nvd\.nist\.gov$/,
    path: /^\/vuln\/detail\//,
    idPatterns: [/CVE-\d{4}-\d{4,}/i],
  },
  {
    label: "GitHub Advisory",
    host: /^github\.com$/,
    path: /^\/advisories\//,
    idPatterns: [/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i],
  },
  {
    label: "Red Hat Errata",
    host: /^access\.redhat\.com$/,
    path: /^\/errata\//,
    idPatterns: [/RHSA-\d{4}:\d+/i],
  },
  {
    label: "Red Hat",
    host: /^access\.redhat\.com$/,
    path: /^\/security\/cve\//,
    idPatterns: [/CVE-\d{4}-\d{4,}/i],
  },
  {
    label: "Debian Tracker",
    host: /^security-tracker\.debian\.org$/,
    path: /^\/tracker\//,
    idPatterns: [/CVE-\d{4}-\d{4,}/i],
  },
  {
    label: "Ubuntu USN",
    host: /^usn\.ubuntu\.com$/,
    path: /^\//,
    idPatterns: [/USN-\d{4,}-\d+/i],
  },
  {
    label: "Ubuntu Security",
    host: /^ubuntu\.com$/,
    path: /^\/security\//,
    idPatterns: [/USN-\d{4,}-\d+/i, /CVE-\d{4}-\d{4,}/i],
  },
  {
    label: "Alpine SecDB",
    host: /^security\.alpinelinux\.org$/,
    path: /^\/vuln\//,
    idPatterns: [/CVE-\d{4}-\d{4,}/i],
  },
  {
    label: "Amazon Linux",
    host: /^alas\.aws\.amazon\.com$/,
    path: /^\//,
    idPatterns: [/ALAS\d*-\d{4}-\d+/i, /ALAS-\d{4}-\d+/i],
  },
  {
    label: "OSV",
    host: /^osv\.dev$/,
    path: /^\/vulnerability\//,
    idPatterns: [
      /CVE-\d{4}-\d{4,}/i,
      /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i,
      /[A-Z]{2,}-\d{4}-\d+/,
    ],
  },
  {
    label: "MITRE",
    host: /^cwe\.mitre\.org$/,
    path: /^\/data\/definitions\//,
    customId: (url) => {
      const match = url.pathname.match(/\/definitions\/(\d+)\.html$/i);
      return match ? `CWE-${match[1]}` : null;
    },
  },
  {
    label: "CISA KEV",
    host: /^www\.cisa\.gov$|^cisa\.gov$/,
    path: /^\/known-exploited-vulnerabilities-catalog/,
    idPatterns: [/CVE-\d{4}-\d{4,}/i],
  },
];

function firstPatternMatch(
  patterns: RegExp[] | undefined,
  text: string
): string | null {
  if (!patterns) return null;
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[0]) return match[0].toUpperCase();
  }
  return null;
}

function normalizeReferenceTitle(title: string): string {
  return title
    .replace(/\s+/g, " ")
    .replace(/^[\s\-|:–—]+/, "")
    .replace(/[\s\-|:–—]+$/, "")
    .trim()
    .slice(0, 140);
}

export function referenceBaseText(url: string): string {
  try {
    const parsed = new URL(url.trim());
    const fullText = `${parsed.pathname}${parsed.search}`;
    for (const rule of REFERENCE_RULES) {
      if (!rule.host.test(parsed.hostname.toLowerCase())) continue;
      if (!rule.path.test(parsed.pathname)) continue;

      const customId = rule.customId?.(parsed) ?? null;
      const extracted =
        customId ||
        firstPatternMatch(rule.idPatterns, fullText) ||
        firstPatternMatch(rule.idPatterns, url);
      if (extracted) {
        return `${rule.label} • ${extracted}`;
      }
      return rule.label;
    }

    const globalId = firstPatternMatch(GLOBAL_REFERENCE_ID_PATTERNS, url);
    return globalId || parsed.hostname;
  } catch {
    const globalId = firstPatternMatch(GLOBAL_REFERENCE_ID_PATTERNS, url);
    return globalId || url;
  }
}

export function referenceDisplayText(
  url: string,
  cachedTitle: string | null | undefined
): string {
  const base = referenceBaseText(url);
  if (!cachedTitle) return base;
  const title = normalizeReferenceTitle(cachedTitle);
  if (!title) return base;
  return `${base}: ${title}`;
}
