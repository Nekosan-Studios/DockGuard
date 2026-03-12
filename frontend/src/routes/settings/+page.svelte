<script lang="ts">
  import { onMount, getContext } from "svelte";
  import type { Writable } from "svelte/store";
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

  import { settings } from "$lib/stores/settings";

  // The `pageTitle` store is provided by `+layout.svelte`.
  const pageTitle = getContext<Writable<string>>("pageTitle");
  if (pageTitle) {
    $pageTitle = "Settings";
  }

  let appVersion = "Development build";

  let isSaving = false;
  let saveMessage: { type: "success" | "error"; text: string } | null = null;
  let hasChanges = false;

  // Local state to track editable fields
  let localValues: Record<string, string> = {};

  onMount(async () => {
    await settings.fetch();
    try {
      const res = await fetch("/api/version");
      if (res.ok) {
        const data = await res.json();
        appVersion = data.version ?? "";
      }
    } catch {
      // ignore – version is cosmetic
    }
  });

  // Reactivity to update localValues when settings fetch
  $: if ($settings && Object.keys($settings).length > 0) {
    // Only initialize localValues if they are empty
    if (Object.keys(localValues).length === 0) {
      for (const [key, conf] of Object.entries($settings)) {
        localValues[key] = conf.value;
      }
    } else {
      // Check if any local values differ from store meaning we have unsaved changes
      let changed = false;
      for (const [key, conf] of Object.entries($settings)) {
        if (localValues[key] !== conf.value) {
          changed = true;
        }
      }
      hasChanges = changed;
    }
  }

  async function handleSave() {
    if (!hasChanges) return;

    isSaving = true;
    saveMessage = null;

    const updates: Record<string, string> = {};
    for (const [key, conf] of Object.entries($settings)) {
      // Only send updates for editable fields that changed
      if (conf.editable && String(localValues[key]) !== String(conf.value)) {
        updates[key] = String(localValues[key]);
      }
    }

    if (Object.keys(updates).length === 0) {
      isSaving = false;
      hasChanges = false;
      return;
    }

    try {
      await settings.updateSettings(updates);
      saveMessage = {
        type: "success",
        text: "Settings saved successfully.",
      };
      hasChanges = false;

      // Auto clear success message
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
    hasChanges = true;
    saveMessage = null;
  }

  // Setting descriptions for friendlier UI labels
  const settingMeta: Record<
    string,
    { label: string; desc: string; group: string }
  > = {
    SCAN_INTERVAL_SECONDS: {
      label: "Docker Poll Interval",
      desc: "How often (in seconds) to check the Docker daemon for new or updated running containers.",
      group: "Scanning",
    },
    MAX_CONCURRENT_SCANS: {
      label: "Max Concurrent Scans",
      desc: "Maximum number of Grype processes to run simultaneously. Set higher if you have resources, lower to save CPU.",
      group: "Scanning",
    },
    DB_CHECK_INTERVAL_SECONDS: {
      label: "Grype DB Check Interval",
      desc: "How often (in seconds) to check for a new Grype vulnerability database update.",
      group: "Updates",
    },
    DATA_RETENTION_DAYS: {
      label: "Data Retention",
      desc: "Scans and task history older than this many days will be automatically purged each day. The most recent scan for each image is always kept.",
      group: "Maintenance",
    },
  };

  // Group settings
  $: groups = (() => {
    const result: Record<string, string[]> = {};
    for (const key of Object.keys($settings)) {
      const group = settingMeta[key]?.group || "Other";
      if (!result[group]) result[group] = [];
      result[group].push(key);
    }
    return result;
  })();
</script>

<div class="space-y-6">
  <div>
    <h3 class="text-lg font-medium">Application Configuration</h3>
    <p class="text-sm text-muted-foreground">
      Manage how DockGuard behaves. Settings configured via `docker-compose.yml`
      or environment variables cannot be modified here.
    </p>
  </div>

  {#if Object.keys($settings).length === 0}
    <div class="flex items-center justify-center p-12 text-muted-foreground">
      <Loader2 class="h-6 w-6 animate-spin mr-2" />
      Loading settings...
    </div>
  {:else}
    <form on:submit|preventDefault={handleSave} class="space-y-8">
      {#each Object.entries(groups) as [groupName, keys] (groupName)}
        <Card.Root>
          <Card.Header>
            <Card.Title>{groupName}</Card.Title>
          </Card.Header>
          <Card.Content class="space-y-6">
            {#each keys as key (key)}
              {@const conf = $settings[key]}
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

                <div class="flex max-w-md">
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
                      type="number"
                      bind:value={localValues[key]}
                      oninput={handleInputChange}
                    />
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

  <div class="text-xs text-muted-foreground text-center pt-4 space-y-1">
    <p>DockGuard v{appVersion}</p>
    <p>
      Copyright © 2026 Nekosan Studios ·
      <a
        href="https://polyformproject.org/licenses/shield/1.0.0/"
        target="_blank"
        rel="noopener noreferrer"
        class="underline hover:text-foreground transition-colors"
        >Polyform Shield 1.0.0</a
      >
    </p>
  </div>
</div>
