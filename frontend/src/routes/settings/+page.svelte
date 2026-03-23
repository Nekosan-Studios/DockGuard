<script lang="ts">
  import { onMount } from "svelte";
  import { slide } from "svelte/transition";
  import * as Card from "$lib/components/ui/card";
  import { Label } from "$lib/components/ui/label";
  import { Input } from "$lib/components/ui/input";
  import { Button } from "$lib/components/ui/button";
  import { Badge } from "$lib/components/ui/badge";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import Lock from "@lucide/svelte/icons/lock";
  import SaveIcon from "@lucide/svelte/icons/save";
  import AlertCircle from "@lucide/svelte/icons/alert-circle";
  import CheckCircle2 from "@lucide/svelte/icons/check-circle-2";

  import { settings } from "$lib/stores/settings.svelte";

  let isSaving = $state(false);
  let saveMessage: { type: "success" | "error"; text: string } | null =
    $state(null);
  let localValues: Record<string, string> = $state({});
  let initialized = $state(false);

  onMount(async () => {
    await settings.fetch();
  });

  // Initialize localValues when settings first load
  $effect(() => {
    const s = settings.data;
    if (s && Object.keys(s).length > 0 && !initialized) {
      const vals: Record<string, string> = {};
      for (const [key, conf] of Object.entries(s)) {
        vals[key] = conf.value;
      }
      localValues = vals;
      initialized = true;
    }
  });

  // Track changes as derived — settings.data and localValues are the only inputs
  let hasChanges = $derived.by(() => {
    if (!initialized || !settings.data) return false;
    return Object.entries(settings.data).some(
      ([key, conf]) => localValues[key] !== conf.value
    );
  });

  async function handleSave() {
    if (!hasChanges) return;

    isSaving = true;
    saveMessage = null;

    const updates: Record<string, string> = {};
    for (const [key, conf] of Object.entries(settings.data)) {
      if (conf.editable && String(localValues[key]) !== String(conf.value)) {
        updates[key] = String(localValues[key]);
      }
    }

    if (Object.keys(updates).length === 0) {
      isSaving = false;
      return;
    }

    try {
      await settings.updateSettings(updates);
      saveMessage = {
        type: "success",
        text: "Settings saved. Changes to Max Concurrent Scans requires a restart to take effect.",
      };
      setTimeout(() => {
        saveMessage = null;
      }, 3000);
    } catch (error: unknown) {
      saveMessage = {
        type: "error",
        text: error instanceof Error ? error.message : "Error saving settings.",
      };
    } finally {
      isSaving = false;
    }
  }

  function handleInputChange() {
    saveMessage = null;
  }

  const textSettings = new Set(["BASE_URL"]);

  // Keys that are durations in seconds and should show a human-readable hint
  const secondsSettings = new Set([
    "SCAN_INTERVAL_SECONDS",
    "DB_CHECK_INTERVAL_SECONDS",
  ]);

  function formatSeconds(seconds: number): string {
    if (!isFinite(seconds) || seconds < 0) return "";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const parts: string[] = [];
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    if (s > 0 || parts.length === 0) parts.push(`${s}s`);
    return parts.join(" ");
  }

  const numericConstraints: Record<
    string,
    { min?: number; max?: number; step?: number }
  > = {
    DAILY_DIGEST_HOUR: { min: 0, max: 23, step: 1 },
  };

  const settingMeta: Record<
    string,
    { label: string; desc: string; group: string }
  > = {
    SCAN_INTERVAL_SECONDS: {
      label: "Registry Update Check Interval",
      desc: "How often (in seconds) to check running images against their registries for newer versions.",
      group: "Scanning",
    },
    MAX_CONCURRENT_SCANS: {
      label: "Max Concurrent Scans",
      desc: "Maximum number of Grype processes to run simultaneously. Set higher if you have resources, lower to save CPU.",
      group: "Scanning",
    },
    DB_CHECK_INTERVAL_SECONDS: {
      label: "Grype DB Check Interval",
      desc: "How often (in seconds) to check for Grype vulnerability database updates.",
      group: "Maintenance",
    },
    SCAN_RETENTION_DAYS: {
      label: "Scan Data Retention",
      desc: "Scan history older than this many days will be automatically purged each day. The most recent scan for each image is always kept regardless of age.",
      group: "Maintenance",
    },
    DAILY_DIGEST_HOUR: {
      label: "Daily Digest Hour",
      desc: "Hour of day (0-23) when the daily vulnerability digest notification is sent. Interpreted in the timezone set by the TZ environment variable, or UTC if TZ is not set.",
      group: "Notifications",
    },
    BASE_URL: {
      label: "Base URL",
      desc: "Base URL of your DockGuard instance (e.g. http://192.168.1.50:8764). Used to include links to vulnerabilities in notifications. Leave empty to omit links.",
      group: "Notifications",
    },
  };

  let groups = $derived.by(() => {
    const result: Record<string, string[]> = {};
    for (const key of Object.keys(settings.data)) {
      const group = settingMeta[key]?.group || "Other";
      if (!result[group]) result[group] = [];
      result[group].push(key);
    }
    return result;
  });
</script>

<div class="container mx-auto py-6 max-w-5xl">
  <div>
    <h3 class="text-lg font-medium">Application Configuration</h3>
    <p class="text-sm text-muted-foreground">
      Manage how DockGuard behaves. Settings configured via `docker-compose.yml`
      or environment variables cannot be modified here.
    </p>
  </div>

  {#if Object.keys(settings.data).length === 0}
    <div class="flex items-center justify-center p-12 text-muted-foreground">
      <Loader2 class="h-6 w-6 animate-spin mr-2" />
      Loading settings...
    </div>
  {:else}
    <form
      onsubmit={(e) => {
        e.preventDefault();
        handleSave();
      }}
      class="space-y-8"
    >
      {#each Object.entries(groups) as [groupName, keys] (groupName)}
        <Card.Root>
          <Card.Header>
            <Card.Title>{groupName}</Card.Title>
          </Card.Header>
          <Card.Content class="space-y-6">
            {#each keys as key (key)}
              {@const conf = settings.data[key]}
              {@const meta = settingMeta[key] || {
                label: key,
                desc: "",
              }}

              <div class="flex flex-col space-y-2 max-w-2xl">
                <div class="flex items-center justify-between">
                  <Label for={key}>{meta.label}</Label>
                  {#if !conf.editable}
                    <div
                      class="flex items-center text-xs text-muted-foreground"
                      title="Configured via environment variable"
                      role="status"
                    >
                      <Lock class="h-3 w-3 mr-1" />
                      <span class="sr-only">Locked</span>
                      Env Var
                    </div>
                  {:else if conf.source === "default"}
                    <Badge
                      variant="outline"
                      class="font-normal text-xs py-0 h-5">Default</Badge
                    >
                  {/if}
                </div>

                <div class="flex items-center gap-3 max-w-md">
                  {#if !conf.editable}
                    <Input
                      id={key}
                      type="text"
                      value={conf.value}
                      disabled
                      class="bg-muted text-muted-foreground"
                    />
                  {:else}
                    <Input
                      id={key}
                      type={textSettings.has(key) ? "text" : "number"}
                      bind:value={localValues[key]}
                      oninput={handleInputChange}
                      {...numericConstraints[key] ?? {}}
                    />
                  {/if}
                  {#if secondsSettings.has(key)}
                    {@const secs = parseInt(localValues[key] ?? conf.value, 10)}
                    {#if secs > 180}
                      <span
                        class="text-xs text-muted-foreground whitespace-nowrap"
                        >= {formatSeconds(secs)}</span
                      >
                    {/if}
                  {/if}
                </div>

                <p class="text-[0.8rem] text-muted-foreground">
                  <code
                    class="text-[0.7rem] bg-muted px-1 py-0.5 rounded mr-1 font-mono"
                    >{key}</code
                  >
                  {meta.desc}
                </p>
              </div>
            {/each}
          </Card.Content>
        </Card.Root>
      {/each}

      <div class="flex items-center gap-4">
        <Button type="submit" disabled={!hasChanges || isSaving}>
          {#if isSaving}
            <Loader2 class="mr-2 h-4 w-4 animate-spin" />
            Saving...
          {:else}
            <SaveIcon class="mr-2 h-4 w-4" />
            Save Changes
          {/if}
        </Button>

        {#if saveMessage}
          <div
            transition:slide={{ duration: 200, axis: "x" }}
            class={`flex items-center text-sm ${saveMessage.type === "success" ? "text-green-600 dark:text-green-500" : "text-destructive"}`}
          >
            {#if saveMessage.type === "success"}
              <CheckCircle2 class="mr-2 h-4 w-4" />
            {:else}
              <AlertCircle class="mr-2 h-4 w-4" />
            {/if}
            {saveMessage.text}
          </div>
        {/if}
      </div>
    </form>
  {/if}
</div>
