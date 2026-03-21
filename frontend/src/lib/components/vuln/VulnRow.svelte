<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Popover from "$lib/components/ui/popover/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import { formatDistanceToNow } from "date-fns";
  import CvssCell from "./CvssCell.svelte";
  import EpssCell from "./EpssCell.svelte";
  import KevCell from "./KevCell.svelte";
  import VexStatusCell from "./VexStatusCell.svelte";
  import PriorityCell from "./PriorityCell.svelte";
  import CveLinkCell from "./CveLinkCell.svelte";
  import {
    PRIORITY_CLASSES,
    priorityFromRiskScore,
    toUtcDate,
  } from "./utils.js";

  // ── Interfaces ────────────────────────────────────────────────────────────
  export interface ContainerInfo {
    image_name: string;
    container_name: string;
  }

  export interface PackageInfo {
    package_name: string;
    installed_version: string;
    fixed_version: string | null;
    package_type: string | null;
    locations: string | null;
    severity: string;
    cvss_base_score: number | null;
  }

  export interface Vulnerability {
    vuln_id: string;
    severity: string;
    description: string | null;
    data_source: string | null;
    cvss_base_score: number | null;
    cvss_vector: string | null;
    epss_score: number | null;
    is_kev: boolean;
    package_name: string; // Used as fallback or top-level string
    installed_version: string;
    fixed_version: string | null;
    package_type: string | null;
    locations: string | null;
    epss_percentile: number | null;
    risk_score: number | null;
    first_seen_at: string | null;
    vex_status: string | null;
    vex_justification: string | null;
    vex_statement: string | null;
    match_type: string | null;
    upstream_name: string | null;
    urls: string | null;
    urls_titles?: Record<string, string> | null;
    cwes: string | null;
    cwe_titles?: Record<string, string> | null;
    fix_state: string | null;
    purl: string | null;
    package_language: string | null;
    is_new?: boolean;
    containers?: ContainerInfo[]; // Optional: Present only in global view
    packages?: PackageInfo[]; // Optional: Present in grouped scenarios
  }

  let {
    vuln,
    showContainers = false,
    hasAnyVex = true,
    onSelect,
  }: {
    vuln: Vulnerability;
    showContainers?: boolean;
    hasAnyVex?: boolean;
    onSelect?: (vuln: Vulnerability) => void;
  } = $props();

  // If the backend didn't supply a `.packages` array but did supply top-level package fields, we wrap it in a mock array to keep the template logic identical.
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

  let rep = $derived(packages[0]);
  let extraPkgs = $derived(packages.length - 1);

  function timeAgo(iso: string | null): string {
    if (!iso) return "";
    return formatDistanceToNow(toUtcDate(iso), { addSuffix: true });
  }
</script>

<Table.Row>
  <CveLinkCell
    vulnId={vuln.vuln_id}
    dataSource={vuln.data_source}
    isNew={vuln.is_new ?? false}
    onDetailClick={() => onSelect?.(vuln)}
  />

  {#if showContainers}
    <Table.Cell class="py-2">
      {#if vuln.containers && vuln.containers.length > 0}
        <div class="flex flex-wrap gap-1">
          {#each vuln.containers as container, ci (ci)}
            <Tooltip.Root>
              <Tooltip.Trigger class="cursor-default">
                <span
                  class="inline-flex max-w-[160px] xl:max-w-[220px] truncate items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                >
                  {container.container_name}
                </span>
              </Tooltip.Trigger>
              <Tooltip.Content>
                <p class="font-medium text-xs mb-0.5">
                  Container: {container.container_name}
                </p>
                <p class="font-mono text-[10px] text-muted-foreground">
                  Image: {container.image_name}
                </p>
              </Tooltip.Content>
            </Tooltip.Root>
          {/each}
        </div>
      {:else}
        <span class="text-muted-foreground text-xs">—</span>
      {/if}
    </Table.Cell>
  {/if}

  <Table.Cell class="font-mono">
    <Tooltip.Root>
      <Tooltip.Trigger class="cursor-default text-left">
        <div class="flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5">
          <div class="max-w-[160px] xl:max-w-[220px] truncate">
            {rep.package_name}
          </div>
          {#if rep.package_type}
            <span
              class="inline-flex items-center rounded border border-slate-200 bg-slate-100 px-1 py-0 font-sans text-[10px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
            >
              {rep.package_type}
            </span>
          {/if}
        </div>
      </Tooltip.Trigger>
      <Tooltip.Content class="max-w-sm">
        {@const paths = rep.locations ? rep.locations.split("\n") : []}
        {#if vuln.upstream_name}
          <div class="mb-2 pb-2 border-b border-border/60">
            <p class="mb-1 font-semibold">CVE matched via source package</p>
            <p class="font-mono text-xs">
              {rep.package_name}
              <span class="text-muted-foreground mx-1">←</span>
              {vuln.upstream_name}
            </p>
          </div>
        {/if}
        <p class="mb-1 font-semibold">
          {rep.package_name}
          {paths.length === 1 ? "Location:" : "Locations:"}
        </p>
        {#if paths.length > 0}
          <ul class="space-y-0.5">
            {#each paths as path, pi (pi)}
              <li class="flex items-start gap-1 font-mono text-xs">
                <span class="shrink-0">•</span>
                <span class="break-all">{path}</span>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="text-xs text-muted-foreground">No locations noted.</p>
        {/if}
      </Tooltip.Content>
    </Tooltip.Root>
    <div
      class="mt-0.5 flex flex-wrap items-center gap-2 text-muted-foreground font-mono text-[11px] leading-tight opacity-90"
    >
      <span>{rep.installed_version}</span>
      <span class="opacity-60">→</span>
      <span class={rep.fixed_version ? "text-foreground" : "italic"}>
        {rep.fixed_version ?? "No fix"}
      </span>
      {#if extraPkgs > 0}
        <Popover.Root>
          <Popover.Trigger>
            <span
              class="inline-flex cursor-pointer items-center rounded border border-indigo-200 bg-indigo-50 px-1.5 py-0.5 font-sans text-[10px] font-medium text-indigo-700 hover:bg-indigo-100 dark:border-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300 dark:hover:bg-indigo-900/60"
            >
              +{extraPkgs} more
            </span>
          </Popover.Trigger>
          <Popover.Content class="w-80 p-0" align="start">
            <p class="px-3 py-2 border-b border-border text-xs font-semibold">
              All Affected Packages ({packages.length})
            </p>
            <div class="max-h-48 overflow-y-auto divide-y divide-border">
              {#each packages as pkg, i (i)}
                <div class="px-3 py-2 text-xs">
                  <div class="flex items-center justify-between gap-1.5">
                    <div class="flex items-baseline gap-1.5">
                      <span class="font-mono font-medium"
                        >{pkg.package_name}</span
                      >
                      {#if pkg.package_type}
                        <span
                          class="inline-flex items-center rounded border border-slate-200 bg-slate-100 px-1 py-0 text-[10px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
                        >
                          {pkg.package_type}
                        </span>
                      {/if}
                    </div>
                    <div class="shrink-0">
                      <span
                        class="inline-flex items-center justify-center gap-1 rounded-full border px-1.5 py-0 font-medium min-w-[50px] {PRIORITY_CLASSES[
                          priorityFromRiskScore(vuln.risk_score)
                        ]}"
                      >
                        <span class="text-[10px] leading-none"
                          >{priorityFromRiskScore(vuln.risk_score)}</span
                        >
                        {#if vuln.risk_score != null}
                          <span
                            class="font-mono opacity-70 text-[9px] leading-none"
                            >{vuln.risk_score.toFixed(1)}</span
                          >
                        {/if}
                      </span>
                    </div>
                  </div>
                  <div
                    class="mt-0.5 flex gap-3 text-muted-foreground font-mono"
                  >
                    <span>{pkg.installed_version}</span>
                    <span>→</span>
                    <span class={pkg.fixed_version ? "text-foreground" : ""}>
                      {pkg.fixed_version ?? "No fix"}
                    </span>
                  </div>
                </div>
              {/each}
            </div>
          </Popover.Content>
        </Popover.Root>
      {/if}
    </div>
  </Table.Cell>

  <PriorityCell riskScore={vuln.risk_score} cvssVector={vuln.cvss_vector} />
  <CvssCell score={vuln.cvss_base_score} />
  <EpssCell score={vuln.epss_score} percentile={vuln.epss_percentile} />
  <KevCell isKev={vuln.is_kev} />

  {#if hasAnyVex}
    <VexStatusCell
      vexStatus={vuln.vex_status}
      vexJustification={vuln.vex_justification}
      vexStatement={vuln.vex_statement}
    />
  {/if}

  <Table.Cell class="text-center">
    {#if vuln.first_seen_at}
      <span class="text-xs text-muted-foreground"
        >{timeAgo(vuln.first_seen_at)}</span
      >
    {:else}
      <span class="text-muted-foreground text-xs">—</span>
    {/if}
  </Table.Cell>

  <Table.Cell
    class="min-w-[260px] xl:min-w-[320px] pr-6 text-muted-foreground whitespace-normal"
    title={vuln.description ?? undefined}
  >
    {#if vuln.description}
      <div
        style="overflow:hidden;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3"
      >
        {vuln.description}
      </div>
    {:else}
      <span class="italic opacity-70">No description available</span>
    {/if}
  </Table.Cell>
</Table.Row>
