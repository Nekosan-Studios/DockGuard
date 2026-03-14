<script lang="ts">
  import * as Dialog from "$lib/components/ui/dialog/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import Clock from "@lucide/svelte/icons/clock";
  import AlertTriangle from "@lucide/svelte/icons/alert-triangle";
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
  } from "./utils.js";

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
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
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
      </Dialog.Title>
    </Dialog.Header>

    <svelte:boundary
      onerror={(e) =>
        console.error("[DockGuard] vulnerability detail render error:", e)}
    >
      <div class="space-y-5">
        <!-- Description -->
        <section>
          <h3
            class="text-muted-foreground mb-1.5 text-xs font-semibold uppercase tracking-wide"
          >
            Description
          </h3>
          {#if vuln.description}
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
                <div class="mt-0.5 text-[11px] text-red-600 dark:text-red-400">
                  CISA Known Exploited Vulnerability
                </div>
              {:else}
                <div class="text-muted-foreground text-xl">No</div>
              {/if}
            </div>
          </div>
        </section>

        <!-- CVSS Vector Breakdown -->
        {#if vectorComponents}
          <section>
            <h3
              class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
            >
              CVSS Vector
            </h3>
            <dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-sm">
              {#each vectorComponents as { label, value } (label)}
                <dt class="text-muted-foreground">{label}</dt>
                <dd class="font-medium">{value}</dd>
              {/each}
            </dl>
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
                    <div class="text-muted-foreground text-[11px] font-medium">
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
        {#if urlList.length > 0 || cweList.length > 0}
          <section>
            <h3
              class="text-muted-foreground mb-2 text-xs font-semibold uppercase tracking-wide"
            >
              References
            </h3>
            {#if urlList.length > 0}
              <ul class="space-y-1">
                {#each urlList as url, ui (ui)}
                  <li>
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      class="inline-flex items-center gap-1 text-sm text-blue-600 hover:underline dark:text-blue-400"
                    >
                      <ExternalLink class="h-3 w-3 shrink-0" />
                      <span class="break-all">{domainFromUrl(url)}</span>
                    </a>
                  </li>
                {/each}
              </ul>
            {/if}
            {#if cweList.length > 0}
              <div class="mt-2 flex flex-wrap gap-1.5">
                {#each cweList as cwe, ci (ci)}
                  {@const cweId = cwe.replace(/^CWE-/, "")}
                  <a
                    href="https://cwe.mitre.org/data/definitions/{cweId}.html"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-1 rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-xs font-mono text-blue-600 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-blue-400 dark:hover:bg-slate-700"
                  >
                    {cwe}
                    <ExternalLink class="h-2.5 w-2.5" />
                  </a>
                {/each}
              </div>
            {/if}
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
                  <ShieldAlert class="h-5 w-5 text-red-600 dark:text-red-400" />
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
  </Dialog.Content>
</Dialog.Root>
