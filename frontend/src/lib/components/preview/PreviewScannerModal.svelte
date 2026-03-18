<script lang="ts">
  import * as Dialog from "$lib/components/ui/dialog/index.js";
  import * as Table from "$lib/components/ui/table/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import ContainerRow from "$lib/components/vuln/ContainerRow.svelte";
  import type { ContainerRecord } from "$lib/components/vuln/ContainerRow.svelte";
  import ScanLine from "@lucide/svelte/icons/scan-line";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import X from "@lucide/svelte/icons/x";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
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
  }

  let previewItems = $state<PreviewItem[]>([]);
  let pollingInterval: ReturnType<typeof setInterval> | null = null;

  function resetState() {
    step = "input";
    inputText = "";
    parsedImages = [];
    parseErrors = [];
    parseLoading = false;
    parseError = null;
    previewItems = [];
    stopPolling();
  }

  $effect(() => {
    if (!open) {
      // Clean up preview scans from DB when modal closes
      const imagesToDelete = previewItems.map((i) => i.image_name);
      if (imagesToDelete.length > 0) {
        fetch("/api/preview-scans", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ image_names: imagesToDelete }),
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
    if (parsedImages.length === 0) return;

    try {
      const res = await fetch("/api/preview-scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ images: parsedImages }),
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
        })
      );
      step = "scanning";
      startPolling();
    } catch (e) {
      parseError = `Failed to start scans: ${e instanceof Error ? e.message : String(e)}`;
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
    const taskIds = previewItems.map((i) => i.task_id);
    if (taskIds.length === 0) return;

    const params = new SvelteURLSearchParams();
    taskIds.forEach((id) => params.append("task_ids", String(id)));

    try {
      const res = await fetch(`/api/preview-scans/status?${params}`);
      if (!res.ok) return;
      const data: PreviewItem[] = await res.json();

      previewItems = previewItems.map((item) => {
        const updated = data.find((d) => d.task_id === item.task_id);
        return updated ?? item;
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
  <Dialog.Content class="sm:max-w-7xl flex flex-col">
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
          <textarea
            bind:value={inputText}
            class="min-h-[180px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 resize-none"
            placeholder="nginx:latest&#10;redis:7-alpine&#10;&#10;— or paste a docker-compose.yml —"
          ></textarea>

          {#if parseError}
            <div
              class="rounded-md border border-red-200 bg-red-50 p-3 dark:border-red-900/50 dark:bg-red-900/10 text-red-800 dark:text-red-300 text-sm flex items-center gap-2"
            >
              <TriangleAlert class="h-4 w-4 shrink-0" />
              {parseError}
            </div>
          {/if}

          <div class="flex items-center justify-between gap-3">
            <label
              class="inline-flex cursor-pointer items-center gap-2 rounded-md border border-input bg-background px-3 py-2 text-sm font-medium hover:bg-accent hover:text-accent-foreground transition-colors"
            >
              <input
                type="file"
                accept=".yml,.yaml"
                class="hidden"
                onchange={handleFileChange}
              />
              Upload compose file…
            </label>

            <div class="flex gap-2">
              <Dialog.Close
                class="inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium hover:bg-accent transition-colors"
              >
                Cancel
              </Dialog.Close>
              <button
                onclick={handleContinue}
                disabled={parseLoading || !inputText.trim()}
                class="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {#if parseLoading}
                  <Loader2 class="h-4 w-4 animate-spin" />
                  Parsing…
                {:else}
                  Continue
                {/if}
              </button>
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
              <div
                class="mb-3 rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-900/10 text-amber-800 dark:text-amber-300 text-xs"
              >
                {#each parseErrors as err (err)}
                  <p>{err}</p>
                {/each}
              </div>
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

          <div class="flex justify-between gap-2">
            <button
              onclick={() => (step = "input")}
              class="inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium hover:bg-accent transition-colors"
            >
              Back
            </button>
            <button
              onclick={startScans}
              disabled={parsedImages.length === 0}
              class="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ScanLine class="h-4 w-4" />
              Scan {parsedImages.length} image{parsedImages.length !== 1
                ? "s"
                : ""}
            </button>
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
                  class="flex items-center justify-between rounded-md border border-border bg-muted/30 px-3 py-2 text-sm font-mono"
                >
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
              {/each}
            </div>
          {/if}

          <!-- Completed results table -->
          {#if completedItems.length > 0}
            <div class="overflow-x-auto">
              <Table.Root>
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
            <Dialog.Close
              class="inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium hover:bg-accent transition-colors"
            >
              Close
            </Dialog.Close>
          </div>
        </div>
      {/if}
    </div>
  </Dialog.Content>
</Dialog.Root>
