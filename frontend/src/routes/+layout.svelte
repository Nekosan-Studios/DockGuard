<script lang="ts">
	import "./layout.css";
	import favicon from "$lib/assets/favicon.svg";
	import { ModeWatcher } from "mode-watcher";
	import * as Sidebar from "$lib/components/ui/sidebar/index.js";
	import * as Tooltip from "$lib/components/ui/tooltip/index.js";
	import AppSidebar from "$lib/components/app-sidebar.svelte";
	import ModeToggle from "$lib/components/mode-toggle.svelte";
	import { navigating } from "$app/stores";

	let { children } = $props();
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
		<Sidebar.Inset>
			<header
				class="flex h-12 shrink-0 items-center justify-between border-b px-4"
			>
				<div class="flex items-center gap-2">
					<Sidebar.Trigger class="-ml-1" />
				</div>
				<ModeToggle />
			</header>
			<main class="flex flex-1 flex-col gap-4 p-6">
				{@render children()}
			</main>
		</Sidebar.Inset>
	</Sidebar.Provider>
</Tooltip.Provider>
