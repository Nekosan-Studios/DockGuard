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
  description: string;
  severity: "none" | "low" | "medium" | "high";
}

function severity(
  v: string,
  highValues: string[],
  mediumValues: string[] = []
): VectorComponent["severity"] {
  if (highValues.includes(v)) return "high";
  if (mediumValues.includes(v)) return "medium";
  if (v === "N" || v === "U") return "none";
  return "low";
}

function buildV31Components(m: Record<string, string>): VectorComponent[] {
  return [
    {
      label: "Attack Vector",
      value:
        { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }[m["AV"]] ??
        m["AV"],
      description:
        {
          N: "Exploitable remotely over the network",
          A: "Requires access to the local network segment",
          L: "Requires local system access",
          P: "Requires physical access to the device",
        }[m["AV"]] ?? "",
      severity: severity(m["AV"], ["N"], ["A"]),
    },
    {
      label: "Attack Complexity",
      value: { L: "Low", H: "High" }[m["AC"]] ?? m["AC"],
      description:
        {
          L: "No special conditions needed to exploit",
          H: "Specific conditions must exist to exploit",
        }[m["AC"]] ?? "",
      severity: severity(m["AC"], ["L"]),
    },
    {
      label: "Privileges Required",
      value: { N: "None", L: "Low", H: "High" }[m["PR"]] ?? m["PR"],
      description:
        {
          N: "No authentication needed",
          L: "Basic user privileges required",
          H: "Admin or elevated privileges required",
        }[m["PR"]] ?? "",
      severity: severity(m["PR"], ["N"], ["L"]),
    },
    {
      label: "User Interaction",
      value: { N: "None", R: "Required" }[m["UI"]] ?? m["UI"],
      description:
        {
          N: "No user action needed — fully automated",
          R: "Victim must perform an action (e.g. click a link)",
        }[m["UI"]] ?? "",
      severity: severity(m["UI"], ["N"]),
    },
    {
      label: "Scope",
      value: { U: "Unchanged", C: "Changed" }[m["S"]] ?? m["S"],
      description:
        {
          U: "Impact limited to the vulnerable component",
          C: "Can affect resources beyond the vulnerable component",
        }[m["S"]] ?? "",
      severity: severity(m["S"], ["C"]),
    },
    {
      label: "Confidentiality",
      value: { N: "None", L: "Low", H: "High" }[m["C"]] ?? m["C"],
      description:
        {
          N: "No information disclosure",
          L: "Some restricted data may be exposed",
          H: "All data in the component could be exposed",
        }[m["C"]] ?? "",
      severity: severity(m["C"], ["H"], ["L"]),
    },
    {
      label: "Integrity",
      value: { N: "None", L: "Low", H: "High" }[m["I"]] ?? m["I"],
      description:
        {
          N: "No data can be modified",
          L: "Some data could be modified without control",
          H: "Attacker can modify any data in the component",
        }[m["I"]] ?? "",
      severity: severity(m["I"], ["H"], ["L"]),
    },
    {
      label: "Availability",
      value: { N: "None", L: "Low", H: "High" }[m["A"]] ?? m["A"],
      description:
        {
          N: "No impact on availability",
          L: "Some degradation of performance or access",
          H: "Complete denial of service possible",
        }[m["A"]] ?? "",
      severity: severity(m["A"], ["H"], ["L"]),
    },
  ];
}

function buildV40Components(m: Record<string, string>): VectorComponent[] {
  return [
    {
      label: "Attack Vector",
      value:
        { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }[m["AV"]] ??
        m["AV"],
      description:
        {
          N: "Exploitable remotely over the network",
          A: "Requires access to the local network segment",
          L: "Requires local system access",
          P: "Requires physical access to the device",
        }[m["AV"]] ?? "",
      severity: severity(m["AV"], ["N"], ["A"]),
    },
    {
      label: "Attack Complexity",
      value: { L: "Low", H: "High" }[m["AC"]] ?? m["AC"],
      description:
        {
          L: "No special conditions needed to exploit",
          H: "Specific conditions must exist to exploit",
        }[m["AC"]] ?? "",
      severity: severity(m["AC"], ["L"]),
    },
    {
      label: "Attack Requirements",
      value: { N: "None", P: "Present" }[m["AT"]] ?? m["AT"],
      description:
        {
          N: "No specific deployment or configuration needed",
          P: "Requires a specific deployment configuration to be vulnerable",
        }[m["AT"]] ?? "",
      severity: severity(m["AT"], ["N"]),
    },
    {
      label: "Privileges Required",
      value: { N: "None", L: "Low", H: "High" }[m["PR"]] ?? m["PR"],
      description:
        {
          N: "No authentication needed",
          L: "Basic user privileges required",
          H: "Admin or elevated privileges required",
        }[m["PR"]] ?? "",
      severity: severity(m["PR"], ["N"], ["L"]),
    },
    {
      label: "User Interaction",
      value: { N: "None", P: "Passive", A: "Active" }[m["UI"]] ?? m["UI"],
      description:
        {
          N: "No user action needed — fully automated",
          P: "Victim interacts with the system but not the attacker's payload directly",
          A: "Victim must directly interact with attacker-controlled content",
        }[m["UI"]] ?? "",
      severity: severity(m["UI"], ["N"], ["P"]),
    },
    {
      label: "Vuln. Confidentiality",
      value: { N: "None", L: "Low", H: "High" }[m["VC"]] ?? m["VC"],
      description:
        {
          N: "No information disclosure in vulnerable system",
          L: "Some restricted data may be exposed",
          H: "All data in the vulnerable system could be exposed",
        }[m["VC"]] ?? "",
      severity: severity(m["VC"], ["H"], ["L"]),
    },
    {
      label: "Vuln. Integrity",
      value: { N: "None", L: "Low", H: "High" }[m["VI"]] ?? m["VI"],
      description:
        {
          N: "No data can be modified in vulnerable system",
          L: "Some data could be modified",
          H: "Attacker can modify any data in the vulnerable system",
        }[m["VI"]] ?? "",
      severity: severity(m["VI"], ["H"], ["L"]),
    },
    {
      label: "Vuln. Availability",
      value: { N: "None", L: "Low", H: "High" }[m["VA"]] ?? m["VA"],
      description:
        {
          N: "No impact on vulnerable system availability",
          L: "Some degradation of performance",
          H: "Complete denial of service on vulnerable system",
        }[m["VA"]] ?? "",
      severity: severity(m["VA"], ["H"], ["L"]),
    },
    {
      label: "Sub. Confidentiality",
      value: { N: "None", L: "Low", H: "High" }[m["SC"]] ?? m["SC"],
      description:
        {
          N: "No information disclosure in subsequent systems",
          L: "Some data in other systems may be exposed",
          H: "All data in subsequent systems could be exposed",
        }[m["SC"]] ?? "",
      severity: severity(m["SC"], ["H"], ["L"]),
    },
    {
      label: "Sub. Integrity",
      value: { N: "None", L: "Low", H: "High" }[m["SI"]] ?? m["SI"],
      description:
        {
          N: "No data modification in subsequent systems",
          L: "Some modification possible in other systems",
          H: "Attacker can modify any data in subsequent systems",
        }[m["SI"]] ?? "",
      severity: severity(m["SI"], ["H"], ["L"]),
    },
    {
      label: "Sub. Availability",
      value: { N: "None", L: "Low", H: "High" }[m["SA"]] ?? m["SA"],
      description:
        {
          N: "No impact on subsequent system availability",
          L: "Some degradation in other systems",
          H: "Complete denial of service on subsequent systems",
        }[m["SA"]] ?? "",
      severity: severity(m["SA"], ["H"], ["L"]),
    },
  ];
}

/** Decode a CVSS v3.x or v4.0 vector string into labeled components. */
export function decodeCvssVector(vector: string): VectorComponent[] | null {
  const versionMatch = vector.match(/^CVSS:(\d+\.\d+)\//);
  const version = versionMatch ? versionMatch[1] : "3.1";
  const raw = vector.replace(/^CVSS:\d+\.\d+\//, "");
  const parts = raw.split("/");
  const map: Record<string, string> = {};
  for (const part of parts) {
    const [k, v] = part.split(":");
    if (k && v) map[k] = v;
  }
  if (!map["AV"]) return null;

  if (version.startsWith("4")) {
    return buildV40Components(map);
  }
  return buildV31Components(map);
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
