<script lang="ts">
  import * as Dialog from "$lib/components/ui/dialog/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import { Skeleton } from "$lib/components/ui/skeleton/index.js";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import Github from "@lucide/svelte/icons/github";
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import Clock from "@lucide/svelte/icons/clock";
  import AlertTriangle from "@lucide/svelte/icons/alert-triangle";
  import { browser } from "$app/environment";
  import { marked } from "marked";
  import DOMPurify from "dompurify";
  import type { Vulnerability } from "./VulnRow.svelte";
  import {
    SEVERITY_CLASSES,
    PRIORITY_CLASSES,
    cvssClass,
    cvssTooltip,
    epssClass,
    epssTooltip,
    priorityFromRiskScore,
    riskScoreTooltip,
    decodeCvssVector,
    toUtcDate,
    referenceDisplayText,
  } from "./utils.js";
  import {
    type EnrichedData,
    type CvssRow,
    enrichmentSource,
    fetchEnrichment,
    formatShortDate,
    nvdStatusClass,
    nvdCvssRows,
    ghsaCvssRows,
    creditTypeLabel,
  } from "./enrichment.js";

  let {
    vuln,
    open = $bindable(false),
    showContainers = false,
  }: {
    vuln: Vulnerability;
    open: boolean;
    showContainers?: boolean;
  } = $props();

  let packages = $derived(
    vuln.packages && vuln.packages.length > 0
      ? vuln.packages
      : [
          {
            package_name: vuln.package_name,
            installed_version: vuln.installed_version,
            fixed_version: vuln.fixed_version,
            package_type: vuln.package_type,
            locations: vuln.locations,
            severity: vuln.severity,
            cvss_base_score: vuln.cvss_base_score,
          },
        ]
  );

  let priority = $derived(priorityFromRiskScore(vuln.risk_score));
  let vectorComponents = $derived(
    vuln.cvss_vector ? decodeCvssVector(vuln.cvss_vector) : null
  );
  let urlList = $derived(
    vuln.urls
      ? [
          ...new Set(
            vuln.urls
              .split(",")
              .map((u) => u.trim())
              .filter(Boolean)
          ),
        ]
      : []
  );
  let cweList = $derived(
    vuln.cwes
      ? [
          ...new Set(
            vuln.cwes
              .split(",")
              .map((c) => c.trim())
              .filter(Boolean)
          ),
        ]
      : []
  );

  function isNew(firstSeenAt: string | null): boolean {
    if (!firstSeenAt) return false;
    const date = toUtcDate(firstSeenAt);
    const hours = (Date.now() - date.getTime()) / (1000 * 60 * 60);
    return hours <= 24;
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Unknown";
    return toUtcDate(iso).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    });
  }

  function domainFromUrl(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  function vexStatusLabel(status: string): string {
    const labels: Record<string, string> = {
      not_affected: "Not Affected",
      affected: "Affected",
      under_investigation: "Under Investigation",
      fixed: "Fixed",
    };
    return labels[status] ?? status;
  }

  function renderMarkdown(md: string): string {
    const raw = marked.parse(md, { async: false }) as string;
    return browser ? DOMPurify.sanitize(raw) : raw;
  }

  // ─── Advisory enrichment ─────────────────────────────────────────────────

  let enrichLoading = $state(false);
  let enriched = $state<EnrichedData | null>(null);
  let enrichError = $state(false);

  $effect(() => {
    const id = vuln.vuln_id;
    const source = enrichmentSource(id);

    if (!open || !source) {
      enrichLoading = false;
      enriched = null;
      enrichError = false;
      return;
    }

    enrichLoading = true;
    enriched = null;
    enrichError = false;

    const controller = new AbortController();

    (async () => {
      try {
        const result = await fetchEnrichment(id, source, controller.signal);
        if (result) {
          enriched = result;
        } else {
          enrichError = true;
        }
      } catch (e: unknown) {
        if (e instanceof DOMException && e.name === "AbortError") return;
        enrichError = true;
      } finally {
        enrichLoading = false;
      }
    })();

    return () => controller.abort();
  });
</script>

<Dialog.Root bind:open>
  <Dialog.Content
    class="w-fit min-w-[min(640px,90vw)] max-w-[90vw] overflow-visible p-0"
  >
    <div class="max-h-[85vh] overflow-y-auto p-6 pr-5">
      {#if enriched !== null && enriched.source === "ghsa" && enriched.data.withdrawn_at}
        <div
          class="mb-4 rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-900/20"
        >
          <div class="flex items-center gap-2">
            <AlertTriangle
              class="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400"
            />
            <p class="text-sm font-medium text-amber-800 dark:text-amber-300">
              Advisory Withdrawn
            </p>
          </div>
          <p class="mt-0.5 text-xs text-amber-700 dark:text-amber-400">
            This advisory was retracted on {formatShortDate(
              enriched.data.withdrawn_at
            )} and may represent a false positive.
          </p>
        </div>
      {/if}
      <Dialog.Header>
        <div class="flex flex-wrap items-center gap-2">
          {#if isNew(vuln.first_seen_at)}
            <span
              class="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
            >
              NEW
            </span>
          {/if}
          <span
            class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[
              vuln.severity
            ]}"
          >
            {vuln.severity}
          </span>
          <span
            class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {PRIORITY_CLASSES[
              priority
            ]}"
          >
            {priority} Priority
          </span>
          {#each cweList as cwe, ci (ci)}
            {@const cweId = cwe.replace(/^CWE-/, "")}
            {@const cweLabel = vuln.cwe_titles?.[cwe]
              ? `${cwe}: ${vuln.cwe_titles[cwe]}`
              : cwe}
            <a
              href="https://cwe.mitre.org/data/definitions/{cweId}.html"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-100 px-2 py-0.5 text-xs font-mono text-blue-600 hover:bg-slate-200 dark:border-slate-700 dark:bg-slate-800 dark:text-blue-400 dark:hover:bg-slate-700"
            >
              {cweLabel}
              <ExternalLink class="h-3 w-3 shrink-0" />
            </a>
          {/each}
        </div>
        <Dialog.Title class="flex items-center gap-2 font-mono text-lg">
          {vuln.vuln_id}
          <a
            href={vuln.data_source ??
              `https://nvd.nist.gov/vuln/detail/${vuln.vuln_id}`}
            target="_blank"
            rel="noopener noreferrer"
            class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
          >
            <ExternalLink class="h-4 w-4" />
          </a>
          {#if enriched !== null && enriched.source === "ghsa"}
            <a
              href={enriched.data.html_url}
              target="_blank"
              rel="noopener noreferrer"
              class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
              aria-label="View on GitHub Advisory Database"
            >
              <Github class="h-4 w-4" />
            </a>
          {:else if enrichLoading && vuln.vuln_id.startsWith("GHSA-")}
            <Skeleton class="h-4 w-4 rounded" />
          {/if}
        </Dialog.Title>
        {#if enriched !== null && enriched.source === "ghsa" && enriched.data.summary && (enriched.data.description || enriched.data.summary !== vuln.description)}
          <p class="text-muted-foreground text-sm">{enriched.data.summary}</p>
        {:else if enrichLoading && vuln.vuln_id.startsWith("GHSA-")}
          <Skeleton class="h-4 w-3/4" />
        {/if}
      </Dialog.Header>

      <svelte:boundary
        onerror={(e) =>
          console.error("[DockGuard] vulnerability detail render error:", e)}
      >
        <div class="mt-4 space-y-5">
          <!-- Containers -->
          {#if showContainers && vuln.containers && vuln.containers.length > 0}
            <section>
              <h3
                class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
              >
                Affected Containers ({vuln.containers.length})
              </h3>
              <div class="space-y-1.5">
                {#each vuln.containers as container, ci2 (ci2)}
                  <div
                    class="flex items-center gap-2 rounded border px-3 py-2 text-sm"
                  >
                    <span class="font-medium">{container.container_name}</span>
                    <span class="text-muted-foreground font-mono text-xs">
                      {container.image_name}
                    </span>
                  </div>
                {/each}
              </div>
            </section>
          {/if}

          <!-- Description -->
          <section>
            <h3
              class="text-muted-foreground mb-1.5 text-xs font-semibold uppercase tracking-wide"
            >
              Description
            </h3>
            {#if enriched !== null && enriched.source === "ghsa" && enriched.data.description}
              <div class="prose prose-sm dark:prose-invert max-w-none">
                <!-- eslint-disable-next-line svelte/no-at-html-tags -- sanitized by DOMPurify -->
                {@html renderMarkdown(enriched.data.description)}
              </div>
            {:else if vuln.description}
              <p class="text-sm leading-relaxed">{vuln.description}</p>
            {:else}
              <p class="text-muted-foreground text-sm italic">
                No description available
              </p>
            {/if}
          </section>

          <!-- Risk Assessment -->
          <section>
            <h3
              class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
            >
              Risk Assessment
            </h3>
            <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <!-- CVSS -->
              <div class="rounded-lg border p-3">
                <div class="text-muted-foreground mb-1 text-[11px] font-medium">
                  CVSS Score
                </div>
                {#if vuln.cvss_base_score != null}
                  <div
                    class="text-xl font-bold {cvssClass(vuln.cvss_base_score)}"
                  >
                    {vuln.cvss_base_score.toFixed(1)}
                  </div>
                  <div class="text-muted-foreground text-[11px]">
                    {cvssTooltip(vuln.cvss_base_score)}
                  </div>
                {:else}
                  <div class="text-muted-foreground text-xl">—</div>
                {/if}
              </div>

              <!-- EPSS -->
              <div class="rounded-lg border p-3">
                <div class="text-muted-foreground mb-1 text-[11px] font-medium">
                  EPSS
                </div>
                {#if vuln.epss_score != null}
                  <div class="text-xl font-bold {epssClass(vuln.epss_score)}">
                    {(vuln.epss_score * 100).toFixed(1)}%
                  </div>
                  <div class="text-muted-foreground text-[11px]">
                    {epssTooltip(vuln.epss_score)}
                    {#if vuln.epss_percentile != null}
                      — {(vuln.epss_percentile * 100).toFixed(0)}th percentile
                    {/if}
                  </div>
                {:else}
                  <div class="text-muted-foreground text-xl">—</div>
                {/if}
              </div>

              <!-- Risk Score -->
              <div class="rounded-lg border p-3">
                <div class="text-muted-foreground mb-1 text-[11px] font-medium">
                  Risk Score
                </div>
                {#if vuln.risk_score != null}
                  <div
                    class="text-xl font-bold {PRIORITY_CLASSES[priority]
                      .split(' ')
                      .find((c) => c.startsWith('text-')) ?? ''}"
                  >
                    {vuln.risk_score.toFixed(1)}
                  </div>
                  <div class="text-muted-foreground text-[11px]">
                    {riskScoreTooltip(vuln.risk_score)}
                  </div>
                {:else}
                  <div class="text-muted-foreground text-xl">—</div>
                {/if}
              </div>

              <!-- KEV -->
              <div
                class="rounded-lg border p-3 {vuln.is_kev
                  ? 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20'
                  : ''}"
              >
                <div class="text-muted-foreground mb-1 text-[11px] font-medium">
                  KEV Status
                </div>
                {#if vuln.is_kev}
                  <div class="flex items-center gap-1.5">
                    <AlertTriangle
                      class="h-5 w-5 text-red-600 dark:text-red-400"
                    />
                    <span
                      class="text-sm font-bold text-red-700 dark:text-red-400"
                    >
                      In KEV Catalog
                    </span>
                  </div>
                  <div
                    class="mt-0.5 text-[11px] text-red-600 dark:text-red-400"
                  >
                    CISA Known Exploited Vulnerability
                  </div>
                  {#if enriched !== null && enriched.source === "nvd" && enriched.data.cve.cisaExploitAdd}
                    {@const cve = enriched.data.cve}
                    <div
                      class="mt-2 space-y-0.5 text-xs text-red-700 dark:text-red-400"
                    >
                      {#if cve.cisaVulnerabilityName}
                        <div class="font-medium">
                          {cve.cisaVulnerabilityName}
                        </div>
                      {/if}
                      <div>
                        Added to KEV: {formatShortDate(cve.cisaExploitAdd!)}
                      </div>
                      {#if cve.cisaActionDue}
                        <div>
                          Action due: {formatShortDate(cve.cisaActionDue)}
                        </div>
                      {/if}
                      {#if cve.cisaRequiredAction}
                        <div class="mt-1 text-[11px] leading-relaxed">
                          {cve.cisaRequiredAction}
                        </div>
                      {/if}
                    </div>
                  {:else if enrichLoading}
                    <div class="mt-2 space-y-1">
                      <Skeleton class="h-3 w-32" />
                      <Skeleton class="h-3 w-24" />
                    </div>
                  {/if}
                {:else}
                  <div class="text-muted-foreground text-xl">No</div>
                  <div class="text-muted-foreground text-[11px]">
                    Not in CISA's catalog of actively exploited vulnerabilities
                  </div>
                {/if}
              </div>
            </div>
          </section>

          <!-- Advisory Details + CVSS Scores (enrichment) -->
          {#if enrichLoading || enriched !== null || enrichError}
            <div class="grid gap-5 lg:grid-cols-2">
              <section>
                <h3
                  class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
                >
                  Advisory Details
                </h3>
                {#if enrichLoading}
                  <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5">
                    {#each [0, 1, 2, 3, 4] as si (si)}
                      <dt><Skeleton class="h-3.5 w-16" /></dt>
                      <dd><Skeleton class="h-3.5 w-40" /></dd>
                    {/each}
                  </dl>
                {:else if enriched !== null && enriched.source === "nvd"}
                  {@const cve = enriched.data.cve}
                  <dl
                    class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm"
                  >
                    <dt class="text-muted-foreground">Published</dt>
                    <dd>{formatShortDate(cve.published)}</dd>
                    <dt class="text-muted-foreground">Last Modified</dt>
                    <dd>{formatShortDate(cve.lastModified)}</dd>
                    <dt class="text-muted-foreground">NVD Status</dt>
                    <dd>
                      <span
                        class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {nvdStatusClass(
                          cve.vulnStatus
                        )}"
                      >
                        {cve.vulnStatus}
                      </span>
                    </dd>
                    {#if cve.sourceIdentifier}
                      <dt class="text-muted-foreground">Assigner</dt>
                      <dd class="font-mono text-xs">{cve.sourceIdentifier}</dd>
                    {/if}
                    {#if cve.cveTags && cve.cveTags.length > 0}
                      {@const allTags = cve.cveTags.flatMap((t) => t.tags)}
                      {#if allTags.length > 0}
                        <dt class="text-muted-foreground">Tags</dt>
                        <dd class="flex flex-wrap gap-1">
                          {#each allTags as tag, ti (ti)}
                            <span
                              class="inline-flex items-center rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:border-amber-700 dark:bg-amber-900/30 dark:text-amber-300"
                            >
                              {tag}
                            </span>
                          {/each}
                        </dd>
                      {/if}
                    {/if}
                  </dl>
                {:else if enriched !== null && enriched.source === "ghsa"}
                  {@const ghsa = enriched.data}
                  <dl
                    class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm"
                  >
                    <dt class="text-muted-foreground">Published</dt>
                    <dd>{formatShortDate(ghsa.published_at)}</dd>
                    <dt class="text-muted-foreground">Last Updated</dt>
                    <dd>{formatShortDate(ghsa.updated_at)}</dd>
                    {#if ghsa.nvd_published_at}
                      <dt class="text-muted-foreground">NVD Published</dt>
                      <dd>{formatShortDate(ghsa.nvd_published_at)}</dd>
                    {/if}
                    <dt class="text-muted-foreground">Review Status</dt>
                    <dd>
                      {#if ghsa.type === "reviewed"}
                        <span
                          class="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
                        >
                          Reviewed
                        </span>
                      {:else}
                        <span
                          class="inline-flex items-center rounded-full border border-slate-200 bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                        >
                          Unreviewed
                        </span>
                      {/if}
                    </dd>
                    {#if ghsa.cve_id}
                      <dt class="text-muted-foreground">Also Known As</dt>
                      <dd class="font-mono text-xs">{ghsa.cve_id}</dd>
                    {/if}
                  </dl>
                  {#if ghsa.vulnerabilities.length > 0}
                    <div class="mt-3">
                      <div
                        class="text-muted-foreground mb-1.5 text-[11px] font-medium"
                      >
                        Affected Ecosystems
                      </div>
                      <div class="space-y-2">
                        {#each ghsa.vulnerabilities as v, vi (vi)}
                          <div class="rounded-lg border p-2.5 text-sm">
                            <div class="flex flex-wrap items-center gap-2">
                              <Badge variant="outline" class="text-[10px]">
                                {v.package.ecosystem}
                              </Badge>
                              <span class="font-mono text-xs font-medium">
                                {v.package.name}
                              </span>
                            </div>
                            <div
                              class="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-xs"
                            >
                              {#if v.vulnerable_version_range}
                                <span class="text-muted-foreground">
                                  {v.vulnerable_version_range}
                                </span>
                                <span class="text-muted-foreground">→</span>
                              {/if}
                              {#if v.first_patched_version}
                                <span
                                  class="text-emerald-700 dark:text-emerald-400"
                                >
                                  {v.first_patched_version}
                                </span>
                              {:else}
                                <span class="text-muted-foreground italic">
                                  No fix available
                                </span>
                              {/if}
                            </div>
                            {#if v.vulnerable_functions && v.vulnerable_functions.length > 0}
                              <div class="mt-1.5">
                                <div
                                  class="text-muted-foreground text-[11px] font-medium"
                                >
                                  Vulnerable functions:
                                </div>
                                <ul class="mt-0.5 space-y-0.5">
                                  {#each v.vulnerable_functions as fn, fi (fi)}
                                    <li class="font-mono text-xs">
                                      <span class="text-muted-foreground mr-1"
                                        >•</span
                                      >{fn}
                                    </li>
                                  {/each}
                                </ul>
                              </div>
                            {/if}
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}
                  {#if ghsa.credits && ghsa.credits.length > 0}
                    <div class="text-muted-foreground mt-2 text-xs">
                      Credits:
                      {#each ghsa.credits as credit, cri (cri)}
                        {#if cri > 0}<span class="mx-1">·</span>{/if}<a
                          href={credit.user.html_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          class="text-blue-600 hover:underline dark:text-blue-400"
                          >{credit.user.login}</a
                        >
                        ({creditTypeLabel(credit.type)})
                      {/each}
                    </div>
                  {/if}
                {:else if enrichError}
                  <p class="text-muted-foreground text-sm italic">
                    Details unavailable from {vuln.vuln_id.startsWith("CVE-")
                      ? "NVD"
                      : "GitHub Advisory Database"}.
                  </p>
                {/if}
              </section>

              <!-- CVSS Scores (enrichment) -->
              {#snippet cvssTable(rows: CvssRow[])}
                <div class="overflow-hidden rounded-md border">
                  <table class="w-full text-sm">
                    <thead>
                      <tr
                        class="bg-muted/50 text-muted-foreground text-[11px] font-medium"
                      >
                        <th class="px-3 py-1.5 text-left">Version</th>
                        <th class="px-3 py-1.5 text-left">Type</th>
                        <th class="px-3 py-1.5 text-left">Source</th>
                        <th class="px-3 py-1.5 text-right">Score</th>
                        <th class="px-3 py-1.5 text-left">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each rows as row, ri (ri)}
                        <tr
                          class="border-t {ri % 2 === 1 ? 'bg-muted/20' : ''}"
                        >
                          <td class="px-3 py-1.5 font-mono text-xs">
                            {row.version}
                          </td>
                          <td class="px-3 py-1.5 text-xs">{row.type}</td>
                          <td
                            class="text-muted-foreground max-w-[12rem] truncate px-3 py-1.5 font-mono text-xs"
                          >
                            {row.source}
                          </td>
                          <td
                            class="px-3 py-1.5 text-right text-xs font-bold {cvssClass(
                              row.score
                            )}"
                          >
                            {row.score.toFixed(1)}
                          </td>
                          <td class="px-3 py-1.5 text-xs">{row.severity}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/snippet}
              <section>
                <h3
                  class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
                >
                  CVSS Scores
                </h3>
                {#if enrichLoading}
                  <div class="space-y-1.5">
                    {#each [0, 1, 2] as si (si)}
                      <Skeleton class="h-8 w-full rounded-md" />
                    {/each}
                  </div>
                {:else if enriched !== null && enriched.source === "nvd"}
                  {@const rows = nvdCvssRows(enriched.data)}
                  {#if rows.length > 0}
                    {@render cvssTable(rows)}
                  {:else}
                    <p class="text-muted-foreground text-sm italic">
                      NVD analysis pending — CVSS scores not yet assigned.
                    </p>
                  {/if}
                {:else if enriched !== null && enriched.source === "ghsa"}
                  {@const rows = ghsaCvssRows(enriched.data)}
                  {#if rows.length > 0}
                    {@render cvssTable(rows)}
                  {/if}
                {/if}
              </section>
            </div>
          {/if}

          <!-- CVSS Vector Breakdown -->
          {#if vectorComponents}
            <section>
              <h3
                class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
              >
                CVSS Vector
              </h3>
              <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {#each vectorComponents as { label, value, description, severity: sev } (label)}
                  <div
                    class="rounded-lg border p-2.5 text-sm
                    {sev === 'high'
                      ? 'border-red-200 bg-red-50/50 dark:border-red-900 dark:bg-red-950/30'
                      : sev === 'medium'
                        ? 'border-amber-200 bg-amber-50/50 dark:border-amber-900 dark:bg-amber-950/30'
                        : 'border-border bg-muted/30'}"
                  >
                    <div class="text-muted-foreground text-xs">{label}</div>
                    <div
                      class="font-semibold
                      {sev === 'high'
                        ? 'text-red-700 dark:text-red-400'
                        : sev === 'medium'
                          ? 'text-amber-700 dark:text-amber-400'
                          : ''}"
                    >
                      {value}
                    </div>
                    {#if description}
                      <div
                        class="text-muted-foreground mt-0.5 text-[11px] leading-tight"
                      >
                        {description}
                      </div>
                    {/if}
                  </div>
                {/each}
              </div>
              <div
                class="text-muted-foreground mt-2 font-mono text-[11px] break-all"
              >
                {vuln.cvss_vector}
              </div>
            </section>
          {/if}

          <!-- Package Details -->
          <section>
            <h3
              class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
            >
              Affected Packages ({packages.length})
            </h3>
            <div class="space-y-2">
              {#each packages as pkg, i (i)}
                <div class="rounded-lg border p-3">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="font-mono text-sm font-medium">
                      {pkg.package_name}
                    </span>
                    {#if pkg.package_type}
                      <Badge variant="outline" class="text-[10px]">
                        {pkg.package_type}
                      </Badge>
                    {/if}
                    {#if vuln.package_language}
                      <Badge variant="outline" class="text-[10px]">
                        {vuln.package_language}
                      </Badge>
                    {/if}
                  </div>
                  <div
                    class="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-sm"
                  >
                    <span class="text-muted-foreground">
                      {pkg.installed_version}
                    </span>
                    <span class="text-muted-foreground">→</span>
                    {#if pkg.fixed_version}
                      <span class="text-emerald-700 dark:text-emerald-400">
                        {pkg.fixed_version}
                      </span>
                    {:else}
                      <span class="text-muted-foreground italic">
                        No fix available
                        {#if vuln.fix_state}
                          ({vuln.fix_state})
                        {/if}
                      </span>
                    {/if}
                  </div>
                  {#if vuln.match_type === "exact-indirect-match" && vuln.upstream_name}
                    <div class="text-muted-foreground mt-1 text-xs">
                      Matched via upstream package:
                      <span class="font-mono font-medium"
                        >{vuln.upstream_name}</span
                      >
                    </div>
                  {/if}
                  {#if vuln.purl}
                    <div
                      class="text-muted-foreground mt-1 font-mono text-[11px] break-all"
                    >
                      {vuln.purl}
                    </div>
                  {/if}
                  {#if pkg.locations}
                    {@const paths = pkg.locations.split("\n").filter(Boolean)}
                    <div class="mt-2">
                      <div
                        class="text-muted-foreground text-[11px] font-medium"
                      >
                        {paths.length === 1 ? "Location:" : "Locations:"}
                      </div>
                      <ul class="mt-0.5 space-y-0.5">
                        {#each paths as path, pi (pi)}
                          <li class="font-mono text-xs break-all">
                            <span class="text-muted-foreground mr-1">•</span
                            >{path}
                          </li>
                        {/each}
                      </ul>
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          </section>

          <!-- References & Advisories -->
          {#if urlList.length > 0}
            <section>
              <h3
                class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
              >
                References
              </h3>
              <div class="flex flex-wrap gap-1.5">
                {#each urlList as url, ui (ui)}
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-1 rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs text-blue-600 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-blue-400 dark:hover:bg-slate-700"
                  >
                    <ExternalLink class="h-3 w-3 shrink-0" />
                    <span
                      >{referenceDisplayText(
                        url,
                        vuln.urls_titles?.[url]
                      )}</span
                    >
                  </a>
                {/each}
              </div>
            </section>
          {/if}

          <!-- VEX Status -->
          {#if vuln.vex_status}
            <section>
              <h3
                class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
              >
                VEX Assessment
              </h3>
              <div class="rounded-lg border p-3">
                <div class="flex items-center gap-2">
                  {#if vuln.vex_status === "not_affected"}
                    <ShieldCheck
                      class="h-5 w-5 text-emerald-600 dark:text-emerald-400"
                    />
                  {:else if vuln.vex_status === "affected"}
                    <ShieldAlert
                      class="h-5 w-5 text-red-600 dark:text-red-400"
                    />
                  {:else if vuln.vex_status === "under_investigation"}
                    <Clock class="h-5 w-5 text-amber-600 dark:text-amber-400" />
                  {:else if vuln.vex_status === "fixed"}
                    <ShieldCheck
                      class="h-5 w-5 text-blue-600 dark:text-blue-400"
                    />
                  {/if}
                  <span class="text-sm font-medium">
                    Supplier declares: {vexStatusLabel(vuln.vex_status)}
                  </span>
                </div>
                {#if vuln.vex_justification}
                  <div class="text-muted-foreground mt-1.5 text-sm">
                    <span class="font-medium">Justification:</span>
                    {vuln.vex_justification}
                  </div>
                {/if}
                {#if vuln.vex_statement}
                  <div
                    class="text-muted-foreground mt-1.5 whitespace-pre-line text-sm"
                  >
                    {vuln.vex_statement}
                  </div>
                {/if}
              </div>
            </section>
          {/if}

          <!-- Metadata -->
          <section class="text-muted-foreground border-t pt-3 text-xs">
            <div class="flex flex-wrap gap-x-6 gap-y-1">
              {#if vuln.first_seen_at}
                <span>First seen: {formatDate(vuln.first_seen_at)}</span>
              {/if}
              {#if vuln.data_source}
                <span>
                  Source:
                  <a
                    href={vuln.data_source}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-blue-600 hover:underline dark:text-blue-400"
                  >
                    {domainFromUrl(vuln.data_source)}
                  </a>
                </span>
              {/if}
            </div>
          </section>
        </div>

        {#snippet failed(error, reset)}
          <div class="flex flex-col items-start gap-3 py-4">
            <div
              class="w-full rounded-md border border-red-200 bg-red-50 p-4 dark:border-red-900/50 dark:bg-red-900/10"
            >
              <div class="flex items-center gap-2">
                <ShieldAlert class="h-5 w-5 text-red-600 dark:text-red-400" />
                <p class="text-sm font-medium text-red-800 dark:text-red-300">
                  An unexpected error occurred while displaying vulnerability
                  details.
                </p>
              </div>
              <p class="mt-1 text-xs text-red-600 dark:text-red-400">
                {error instanceof Error ? error.message : String(error)}
              </p>
            </div>
            <button
              class="text-xs underline text-muted-foreground"
              onclick={reset}>Try again</button
            >
          </div>
        {/snippet}
      </svelte:boundary>
    </div>
  </Dialog.Content>
</Dialog.Root>
