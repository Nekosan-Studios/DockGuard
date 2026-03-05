<script lang="ts">
	import * as Card from "$lib/components/ui/card/index.js";
	import * as Table from "$lib/components/ui/table/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import ListTodo from "@lucide/svelte/icons/list-todo";
	import Clock from "@lucide/svelte/icons/clock";
	import PlayCircle from "@lucide/svelte/icons/play-circle";
	import CheckCircle2 from "@lucide/svelte/icons/check-circle-2";
	import XCircle from "@lucide/svelte/icons/x-circle";

	let { data } = $props();

	let sortedTasks = $derived(
		[...(data.tasks || [])].sort((a, b) => {
			const order: Record<string, number> = {
				running: 0,
				queued: 1,
				failed: 2,
				completed: 3,
			};
			const aRank = order[a.status] ?? 4;
			const bRank = order[b.status] ?? 4;
			if (aRank !== bRank) return aRank - bRank;

			const aDate = new Date(a.finished_at || a.created_at).getTime();
			const bDate = new Date(b.finished_at || b.created_at).getTime();
			return bDate - aDate;
		}),
	);

	function formatDate(dateStr: string | null | undefined) {
		if (!dateStr) return "-";
		const d = new Date(dateStr);
		return new Intl.DateTimeFormat("default", {
			month: "short",
			day: "numeric",
			hour: "numeric",
			minute: "2-digit",
			second: "2-digit",
		}).format(d);
	}

	function getStatusIcon(status: string) {
		switch (status) {
			case "queued":
				return Clock;
			case "running":
				return PlayCircle;
			case "completed":
				return CheckCircle2;
			case "failed":
				return XCircle;
			default:
				return Clock;
		}
	}

	function getStatusVariant(status: string) {
		switch (status) {
			case "running":
				return "default";
			case "failed":
				return "destructive";
			default:
				return "outline";
		}
	}

	function getStatusClass(status: string) {
		switch (status) {
			case "queued":
				return "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800";
			case "completed":
				return "bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-900/40 dark:text-emerald-300 dark:border-emerald-800";
			default:
				return "";
		}
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Tasks</h1>
		<p class="text-muted-foreground mt-1">
			Background jobs, scan queue, and task history.
		</p>
	</div>

	<!-- Scheduled Tasks -->
	<Card.Root>
		<Card.Header>
			<Card.Title>Scheduled Tasks</Card.Title>
			<Card.Description
				>Periodic background jobs checking for updates and new
				containers.</Card.Description
			>
		</Card.Header>
		<Card.Content>
			{#if data.scheduledJobs.length === 0}
				<div
					class="flex flex-col items-center justify-center gap-3 py-10 text-center text-muted-foreground"
				>
					<Clock class="h-8 w-8 opacity-50" />
					<p>No scheduled tasks found.</p>
				</div>
			{:else}
				<div class="rounded-md border">
					<Table.Root>
						<Table.Header>
							<Table.Row>
								<Table.Head>Name</Table.Head>
								<Table.Head>Interval</Table.Head>
								<Table.Head>Next Run</Table.Head>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{#each data.scheduledJobs as job (job.id)}
								<Table.Row>
									<Table.Cell class="font-medium"
										>{job.name}</Table.Cell
									>
									<Table.Cell>
										{#if job.interval_seconds}
											Every {Math.floor(
												job.interval_seconds / 60,
											)} minutes
										{:else}
											-
										{/if}
									</Table.Cell>
									<Table.Cell
										>{formatDate(
											job.next_run_time,
										)}</Table.Cell
									>
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Task History & Queue -->
	<Card.Root>
		<Card.Header>
			<Card.Title>Queue & History</Card.Title>
			<Card.Description
				>Recent scans and scheduled job executions.</Card.Description
			>
		</Card.Header>
		<Card.Content>
			{#if data.tasks.length === 0}
				<div
					class="flex flex-col items-center justify-center gap-3 py-10 text-center text-muted-foreground"
				>
					<ListTodo class="h-8 w-8 opacity-50" />
					<p>No recent tasks in the database.</p>
				</div>
			{:else}
				<div class="rounded-md border">
					<Table.Root>
						<Table.Header>
							<Table.Row>
								<Table.Head>Status</Table.Head>
								<Table.Head>Task Name</Table.Head>
								<Table.Head>Created</Table.Head>
								<Table.Head>Finished</Table.Head>
								<Table.Head>Results / Errors</Table.Head>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{#each sortedTasks as task (task.id)}
								<Table.Row>
									<Table.Cell>
										<Badge
											variant={getStatusVariant(
												task.status,
											)}
											class={getStatusClass(task.status)}
										>
											{task.status}
										</Badge>
									</Table.Cell>
									<Table.Cell class="font-medium"
										>{task.task_name}</Table.Cell
									>
									<Table.Cell
										>{formatDate(
											task.created_at,
										)}</Table.Cell
									>
									<Table.Cell
										>{formatDate(
											task.finished_at,
										)}</Table.Cell
									>
									<Table.Cell>
										{#if task.status === "failed"}
											<span
												class="text-destructive text-sm"
												>{task.error_message ||
													"Unknown error"}</span
											>
										{:else if task.result_details}
											<span
												class="text-sm truncate max-w-[500px] inline-block"
												title={task.result_details}
												>{task.result_details}</span
											>
										{:else}
											<span
												class="text-muted-foreground text-sm"
												>-</span
											>
										{/if}
									</Table.Cell>
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
