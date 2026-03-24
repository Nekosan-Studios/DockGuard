<script lang="ts">
  import * as Alert from "$lib/components/ui/alert/index.js";
  import { Button } from "$lib/components/ui/button/index.js";
  import { Checkbox } from "$lib/components/ui/checkbox/index.js";
  import * as Dialog from "$lib/components/ui/dialog/index.js";
  import * as Table from "$lib/components/ui/table/index.js";
  import { Textarea } from "$lib/components/ui/textarea/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import ContainerRow from "$lib/components/vuln/ContainerRow.svelte";
  import type { ContainerRecord } from "$lib/components/vuln/ContainerRow.svelte";
  import ScanLine from "@lucide/svelte/icons/scan-line";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import X from "@lucide/svelte/icons/x";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import CheckCircle2 from "@lucide/svelte/icons/check-circle-2";
  import { SvelteURLSearchParams } from "svelte/reactivity";

  let { open = $bindable(false) }: { open: boolean } = $props();

  type Step = "input" | "review" | "scanning";
  let step = $state<Step>("input");

  let inputText = $state("");
  let parsedImages = $state<string[]>([]);
  let parseErrors = $state<string[]>([]);
  let parseLoading = $state(false);
  let parseError = $state<string | null>(null);

  interface PreviewItem {
    task_id: number;
    image_name: string;
    status: "pending" | "scanning" | "complete" | "failed";
    error_message: string | null;
    scan_data: ContainerRecord | null;
    progress_lines: string[];
  }

  let previewItems = $state<PreviewItem[]>([]);
  let pollingInterval: ReturnType<typeof setInterval> | null = null;
  let skipEnrichments = $state(false);
  let maxConcurrent = $state(1);
  let submitting = $state(false);

  function resetState() {
    step = "input";
    inputText = "";
    parsedImages = [];
    parseErrors = [];
    parseLoading = false;
    parseError = null;
    previewItems = [];
    skipEnrichments = false;
    maxConcurrent = 1;
    stopPolling();
  }

  $effect(() => {
    if (!open) {
      // Clean up preview scans from DB when modal closes; cancel in-flight tasks
      const imagesToDelete = previewItems.map((i) => i.image_name);
      const inFlightTaskIds = previewItems
        .filter((i) => i.status !== "complete" && i.status !== "failed")
        .map((i) => i.task_id);
      if (imagesToDelete.length > 0) {
        fetch("/api/preview-scans", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            image_names: imagesToDelete,
            task_ids: inFlightTaskIds,
          }),
        }).catch(() => {});
      }
      stopPolling();
      // Reset after a short delay to avoid flash during close animation
      setTimeout(resetState, 300);
    }
  });

  function stopPolling() {
    if (pollingInterval !== null) {
      clearInterval(pollingInterval);
      pollingInterval = null;
    }
  }

  function handleFileChange(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      inputText = (evt.target?.result as string) ?? "";
    };
    reader.readAsText(file);
  }

  async function handleContinue() {
    if (!inputText.trim()) return;

    parseLoading = true;
    parseError = null;
    parseErrors = [];

    // Try to detect YAML (has "services:" key) and parse via backend
    const looksLikeCompose = /^\s*services\s*:/m.test(inputText);

    if (looksLikeCompose) {
      try {
        const res = await fetch("/api/preview-scans/parse-compose", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ yaml_text: inputText }),
        });
        if (!res.ok) {
          const err = await res.json();
          parseError = err.detail ?? "Failed to parse compose file.";
          parseLoading = false;
          return;
        }
        const data = await res.json();
        parsedImages = data.images ?? [];
        parseErrors = data.parse_errors ?? [];
        if (parsedImages.length === 0) {
          parseError = "No image references found in compose file.";
          parseLoading = false;
          return;
        }
      } catch {
        parseError = "Failed to parse compose file.";
        parseLoading = false;
        return;
      }
    } else {
      // Plain image names — split on any combination of newlines and spaces
      parsedImages = inputText
        .split(/[\s\n]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .filter((v, i, a) => a.indexOf(v) === i); // deduplicate
      if (parsedImages.length === 0) {
        parseError = "No image names found. Enter one image name per line.";
        parseLoading = false;
        return;
      }
    }

    parseLoading = false;
    step = "review";
  }

  function removeImage(img: string) {
    parsedImages = parsedImages.filter((i) => i !== img);
  }

  async function startScans() {
    if (parsedImages.length === 0 || submitting) return;

    submitting = true;

    // Transition immediately — user sees "Queued..." badges at once
    previewItems = parsedImages.map((img) => ({
      task_id: 0,
      image_name: img,
      status: "pending" as const,
      error_message: null,
      scan_data: null,
      progress_lines: [] as string[],
    }));
    step = "scanning";

    try {
      const res = await fetch("/api/preview-scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          images: parsedImages,
          skip_enrichments: skipEnrichments,
          max_concurrent: maxConcurrent,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      previewItems = (data.preview_items ?? []).map(
        (item: { image_name: string; task_id: number }) => ({
          task_id: item.task_id,
          image_name: item.image_name,
          status: "pending" as const,
          error_message: null,
          scan_data: null,
          progress_lines: [] as string[],
        })
      );
      startPolling();
    } catch (e) {
      step = "review";
      parseError = `Failed to start scans: ${e instanceof Error ? e.message : String(e)}`;
    } finally {
      submitting = false;
    }
  }

  function startPolling() {
    pollStatus();
    pollingInterval = setInterval(() => {
      const allDone = previewItems.every(
        (i) => i.status === "complete" || i.status === "failed"
      );
      if (allDone) {
        stopPolling();
        return;
      }
      pollStatus();
    }, 3000);
  }

  async function pollStatus() {
    const taskIds = previewItems.map((i) => i.task_id).filter((id) => id > 0);
    if (taskIds.length === 0) return;

    const params = new SvelteURLSearchParams();
    taskIds.forEach((id) => params.append("task_ids", String(id)));

    try {
      const res = await fetch(`/api/preview-scans/status?${params}`);
      if (!res.ok) return;
      const data: PreviewItem[] = await res.json();

      previewItems = previewItems.map((item) => {
        const updated = data.find((d) => d.task_id === item.task_id);
        if (!updated) return item;
        return {
          ...updated,
          progress_lines: updated.progress_lines ?? item.progress_lines,
        };
      });

      // Stop polling if all done
      const allDone = previewItems.every(
        (i) => i.status === "complete" || i.status === "failed"
      );
      if (allDone) stopPolling();
    } catch {
      // Ignore transient polling errors
    }
  }

  let fileInputEl = $state<HTMLInputElement | null>(null);

  let allDone = $derived(
    previewItems.length > 0 &&
      previewItems.every(
        (i) => i.status === "complete" || i.status === "failed"
      )
  );

  let completedItems = $derived(
    previewItems.filter((i) => i.status === "complete" && i.scan_data !== null)
  );

  let pendingItems = $derived(
    previewItems.filter((i) => i.status !== "complete")
  );
</script>

<Dialog.Root bind:open>
  <Dialog.Content
    class="{step === 'scanning'
      ? 'sm:max-w-[95vw] 2xl:max-w-[1700px]'
      : 'sm:max-w-xl'} flex flex-col transition-[max-width] duration-300"
  >
    <Dialog.Header class="shrink-0">
      <Dialog.Title class="flex items-center gap-2">
        <ScanLine class="h-5 w-5" />
        Preview Image Scanner
      </Dialog.Title>
      <Dialog.Description>
        Scan images before deploying them. Paste image names or a
        docker-compose.yml to check for vulnerabilities.
      </Dialog.Description>
    </Dialog.Header>

    <div
      class="overflow-auto max-h-[calc(90vh-8rem)] min-w-0 [&::-webkit-scrollbar]:h-1.5 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-border [&::-webkit-scrollbar-track]:bg-transparent"
    >
      {#if step === "input"}
        <div class="flex flex-col gap-4 mt-2">
          <Textarea
            bind:value={inputText}
            class="min-h-[180px] font-mono resize-none"
            placeholder="nginx:latest&#10;redis:7-alpine&#10;&#10;— or paste a docker-compose.yml —"
          />

          {#if parseError}
            <Alert.Root variant="destructive">
              <TriangleAlert />
              <Alert.Description>{parseError}</Alert.Description>
            </Alert.Root>
          {/if}

          <div class="flex items-center justify-between gap-3">
            <Button variant="outline" onclick={() => fileInputEl?.click()}>
              Upload compose file…
            </Button>
            <input
              bind:this={fileInputEl}
              type="file"
              accept=".yml,.yaml"
              class="hidden"
              onchange={handleFileChange}
            />

            <div class="flex gap-2">
              <Dialog.Close>
                {#snippet child({ props })}
                  <Button variant="outline" {...props}>Cancel</Button>
                {/snippet}
              </Dialog.Close>
              <Button
                onclick={handleContinue}
                disabled={parseLoading || !inputText.trim()}
              >
                {#if parseLoading}
                  <Loader2 class="h-4 w-4 animate-spin" />
                  Parsing…
                {:else}
                  Continue
                {/if}
              </Button>
            </div>
          </div>
        </div>
      {:else if step === "review"}
        <div class="flex flex-col gap-4 mt-2">
          <div>
            <p class="text-sm text-muted-foreground mb-2">
              {parsedImages.length} image{parsedImages.length !== 1 ? "s" : ""} detected.
              Remove any you don't want to scan.
            </p>
            {#if parseErrors.length > 0}
              <Alert.Root variant="caution" class="mb-3 text-xs">
                <Alert.Description>
                  {#each parseErrors as err (err)}
                    <p>{err}</p>
                  {/each}
                </Alert.Description>
              </Alert.Root>
            {/if}
            <div class="flex flex-wrap gap-2 max-h-48 overflow-y-auto">
              {#each parsedImages as img (img)}
                <span
                  class="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-3 py-1 text-xs font-mono"
                >
                  {img}
                  <button
                    onclick={() => removeImage(img)}
                    class="ml-1 text-muted-foreground hover:text-foreground transition-colors rounded-full"
                    aria-label="Remove {img}"
                  >
                    <X class="h-3 w-3" />
                  </button>
                </span>
              {/each}
            </div>
          </div>

          <div class="flex flex-col gap-3 border-t border-border pt-3">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium">Parallel scans</p>
                <p class="text-xs text-muted-foreground">
                  Run up to {maxConcurrent} scan{maxConcurrent !== 1 ? "s" : ""} simultaneously
                </p>
              </div>
              <div class="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="icon-sm"
                  onclick={() =>
                    (maxConcurrent = Math.max(1, maxConcurrent - 1))}
                  disabled={maxConcurrent <= 1}
                  aria-label="Decrease parallel scans"
                >
                  −
                </Button>
                <span class="w-4 text-center text-sm font-mono"
                  >{maxConcurrent}</span
                >
                <Button
                  variant="outline"
                  size="icon-sm"
                  onclick={() =>
                    (maxConcurrent = Math.min(4, maxConcurrent + 1))}
                  disabled={maxConcurrent >= 4}
                  aria-label="Increase parallel scans"
                >
                  +
                </Button>
              </div>
            </div>
            <label class="flex cursor-pointer items-start gap-2">
              <Checkbox
                class="mt-0.5"
                checked={skipEnrichments}
                onCheckedChange={(v) => (skipEnrichments = v === true)}
              />
              <div>
                <p class="text-sm font-medium">Quick scan</p>
                <p class="text-xs text-muted-foreground">
                  Skip extra HTTP calls
                </p>
              </div>
            </label>
          </div>

          <div class="flex justify-between gap-2">
            <Button variant="outline" onclick={() => (step = "input")}>
              Back
            </Button>
            <Button
              onclick={startScans}
              disabled={parsedImages.length === 0 || submitting}
            >
              <ScanLine class="h-4 w-4" />
              Scan {parsedImages.length} image{parsedImages.length !== 1
                ? "s"
                : ""}
            </Button>
          </div>
        </div>
      {:else}
        <!-- Scanning / Results step -->
        <div class="flex flex-col gap-4 mt-2">
          <div
            class="flex items-center justify-between rounded-md border border-amber-200 bg-amber-50 px-3 py-2 dark:border-amber-800 dark:bg-amber-900/10"
          >
            <span
              class="text-xs font-medium text-amber-800 dark:text-amber-300"
            >
              PREVIEW — results are temporary and not stored after closing this
              dialog
            </span>
            {#if !allDone}
              <span
                class="flex items-center gap-1 text-xs text-amber-700 dark:text-amber-400"
              >
                <Loader2 class="h-3 w-3 animate-spin" />
                Scanning…
              </span>
            {:else}
              <span class="text-xs text-amber-700 dark:text-amber-400"
                >Complete</span
              >
            {/if}
          </div>

          <!-- Pending/scanning/failed rows (non-table list) -->
          {#if pendingItems.length > 0}
            <div class="flex flex-col gap-1">
              {#each pendingItems as item (item.task_id)}
                <div
                  class="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm font-mono"
                >
                  <div class="flex items-center justify-between">
                    <span class="truncate text-xs">{item.image_name}</span>
                    {#if item.status === "pending"}
                      <Badge variant="outline" class="text-xs shrink-0"
                        >Queued</Badge
                      >
                    {:else if item.status === "scanning"}
                      <span
                        class="flex items-center gap-1 text-xs text-muted-foreground shrink-0"
                      >
                        <Loader2 class="h-3 w-3 animate-spin" />
                        Scanning…
                      </span>
                    {:else if item.status === "failed"}
                      <div class="flex flex-col items-end gap-0.5 shrink-0">
                        <Badge
                          variant="outline"
                          class="text-xs border-red-300 text-red-700 bg-red-50 dark:border-red-700 dark:text-red-400 dark:bg-red-900/20"
                        >
                          Failed
                        </Badge>
                        {#if item.error_message}
                          <span
                            class="text-xs text-red-600 dark:text-red-400 max-w-xs text-right leading-tight"
                          >
                            {item.error_message}
                          </span>
                        {/if}
                      </div>
                    {/if}
                  </div>
                  {#if item.status === "scanning" && item.progress_lines.length > 0}
                    <div class="mt-1 flex flex-col gap-0.5">
                      {#each item.progress_lines as line, i (line)}
                        <div class="flex items-center gap-1.5 text-xs">
                          {#if i < item.progress_lines.length - 1}
                            <CheckCircle2
                              class="h-3 w-3 shrink-0 text-green-500"
                            />
                            <span class="text-muted-foreground">{line}</span>
                          {:else}
                            <Loader2
                              class="h-3 w-3 shrink-0 animate-spin text-muted-foreground"
                            />
                            <span class="text-muted-foreground">{line}</span>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}

          <!-- Completed results table -->
          {#if completedItems.length > 0}
            <div class="preview-results overflow-x-auto">
              <Table.Root class="w-full table-fixed">
                <colgroup>
                  <col class="w-[280px] lg:w-[340px]" />
                  <col class="w-auto" />
                  <col class="w-[170px]" />
                </colgroup>
                <Table.Header>
                  <Table.Row>
                    <Table.Head>Image</Table.Head>
                    <Table.Head>Vulnerabilities</Table.Head>
                    <Table.Head class="w-[180px] text-center"
                      >Scanned</Table.Head
                    >
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {#each completedItems as item (item.task_id)}
                    {#if item.scan_data}
                      <ContainerRow
                        container={item.scan_data}
                        hideVexResolved={false}
                        activeCve={null}
                        showHistory={false}
                      />
                    {/if}
                  {/each}
                </Table.Body>
              </Table.Root>
            </div>
          {/if}

          <div class="flex justify-end">
            <Dialog.Close>
              {#snippet child({ props })}
                <Button variant="outline" {...props}>Close</Button>
              {/snippet}
            </Dialog.Close>
          </div>
        </div>
      {/if}
    </div>
  </Dialog.Content>
</Dialog.Root>
