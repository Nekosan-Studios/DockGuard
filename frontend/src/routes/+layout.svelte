<script lang="ts">
  import "./layout.css";
  import favicon from "$lib/assets/favicon.svg";
  import { ModeWatcher } from "mode-watcher";
  import * as Sidebar from "$lib/components/ui/sidebar/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import AppSidebar from "$lib/components/app-sidebar.svelte";
  import ModeToggle from "$lib/components/mode-toggle.svelte";
  import { navigating } from "$app/stores";
  import { onMount } from "svelte";

  let { children } = $props();

  let appVersion = $state("Development build");

  onMount(async () => {
    try {
      const res = await fetch("/api/version");
      if (res.ok) {
        const data = await res.json();
        const version = data?.version;
        if (typeof version === "string" && version.trim() !== "") {
          appVersion = version;
        }
      }
    } catch {
      // ignore – version is cosmetic
    }
  });
</script>

<svelte:head>
  <link rel="icon" href={favicon} />
  {#if $navigating}
    <style>
      body * {
        cursor: wait !important;
      }
    </style>
  {/if}
</svelte:head>

<ModeWatcher />

<Tooltip.Provider delayDuration={400}>
  <Sidebar.Provider>
    <AppSidebar />
    <Sidebar.Inset class="min-w-0">
      <header
        class="flex h-12 shrink-0 items-center justify-between border-b px-4"
      >
        <div class="flex items-center gap-2">
          <Sidebar.Trigger class="-ml-1" />
        </div>
        <ModeToggle />
      </header>
      <main class="flex flex-1 flex-col gap-4 p-6 min-w-0">
        {@render children()}
      </main>
      <footer class="text-xs text-muted-foreground text-center py-4 space-y-1">
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
      </footer>
    </Sidebar.Inset>
  </Sidebar.Provider>
</Tooltip.Provider>
