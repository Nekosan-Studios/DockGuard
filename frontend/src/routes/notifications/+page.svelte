<script lang="ts">
  import { onMount } from "svelte";
  import { on } from "svelte/events";
  import * as Card from "$lib/components/ui/card";
  import * as Table from "$lib/components/ui/table/index.js";
  import * as AlertDialog from "$lib/components/ui/alert-dialog";
  import * as Collapsible from "$lib/components/ui/collapsible";
  import { Label } from "$lib/components/ui/label";
  import { Input } from "$lib/components/ui/input";
  import { Button } from "$lib/components/ui/button";
  import { Badge } from "$lib/components/ui/badge";
  import { Switch } from "$lib/components/ui/switch";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import Plus from "@lucide/svelte/icons/plus";
  import Trash2 from "@lucide/svelte/icons/trash-2";
  import Send from "@lucide/svelte/icons/send";
  import ChevronDown from "@lucide/svelte/icons/chevron-down";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import * as Pagination from "$lib/components/ui/pagination";
  import {
    notifications,
    type NotificationChannel,
  } from "$lib/stores/notifications.svelte";

  let loading = $state(true);
  let showAddForm = $state(false);
  let testingId: number | null = $state(null);
  let testMessage: {
    id: number;
    type: "success" | "error";
    text: string;
  } | null = $state(null);
  let deleteConfirmId: number | null = $state(null);
  let savingId: number | null = $state(null);

  // New channel form state
  let newName = $state("");
  let newUrl = $state("");
  let newError: string | null = $state(null);
  let creating = $state(false);

  // Log pagination
  let logPage = $state(1);

  onMount(() => {
    const refresh = () => {
      if (!document.hidden) {
        notifications.fetchLog(logPage);
        notifications.fetchChannels();
      }
    };
    const interval = setInterval(refresh, 30_000);
    const cleanup = on(document, "visibilitychange", refresh);

    Promise.all([notifications.fetchChannels(), notifications.fetchLog()]).then(
      () => {
        loading = false;
      }
    );

    return () => {
      clearInterval(interval);
      cleanup();
    };
  });

  let _logPageInit = false;
  $effect(() => {
    const p = logPage;
    if (!_logPageInit) {
      _logPageInit = true;
      return; // skip initial effect; onMount handles page 1
    }
    notifications.fetchLog(p);
  });

  async function handleCreate() {
    if (!newName.trim() || !newUrl.trim()) {
      newError = "Name and Apprise URL are required.";
      return;
    }
    creating = true;
    newError = null;
    try {
      await notifications.createChannel({
        name: newName.trim(),
        apprise_url: newUrl.trim(),
        enabled: true,
        notify_urgent: false,
        notify_kev: false,
        notify_all_new: false,
        notify_digest: false,
        notify_eol: false,
        notify_scan_failure: false,
      });
      newName = "";
      newUrl = "";
      showAddForm = false;
    } catch (err: unknown) {
      newError =
        err instanceof Error ? err.message : "Failed to create channel.";
    } finally {
      creating = false;
    }
  }

  async function handleToggle(
    channel: NotificationChannel,
    field: keyof NotificationChannel,
    value: boolean
  ) {
    savingId = channel.id;
    try {
      await notifications.updateChannel(channel.id, { [field]: value });
    } catch {
      // Revert on error by re-fetching
      await notifications.fetchChannels();
    } finally {
      savingId = null;
    }
  }

  async function handleTest(id: number) {
    testingId = id;
    testMessage = null;
    try {
      await notifications.testChannel(id);
      testMessage = { id, type: "success", text: "Test notification sent!" };
      // Refresh log to show the test entry
      await notifications.fetchLog(logPage);
      setTimeout(() => {
        testMessage = null;
      }, 3000);
    } catch (err: unknown) {
      testMessage = {
        id,
        type: "error",
        text: err instanceof Error ? err.message : "Test failed.",
      };
    } finally {
      testingId = null;
    }
  }

  async function handleDelete(id: number) {
    try {
      await notifications.deleteChannel(id);
      await notifications.fetchLog(logPage);
    } catch {
      // silently fail; UI will stay consistent
    }
    deleteConfirmId = null;
  }

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

  function typeVariant(
    t: string
  ): "default" | "destructive" | "outline" | "secondary" {
    switch (t) {
      case "urgent":
        return "destructive";
      case "kev":
        return "destructive";
      case "scan_failure":
        return "destructive";
      case "eol":
        return "secondary";
      case "test":
        return "outline";
      default:
        return "default";
    }
  }

  function typeLabel(t: string): string {
    const labels: Record<string, string> = {
      urgent: "Urgent",
      kev: "KEV",
      new_vulns: "New Vulns",
      digest: "Digest",
      eol: "EOL",
      scan_failure: "Failure",
      test: "Test",
    };
    return labels[t] ?? t;
  }

  const toggleFields: {
    key: keyof NotificationChannel;
    label: string;
    description: string;
  }[] = [
    {
      key: "notify_urgent",
      label: "Urgent Priority",
      description:
        "New vulnerabilities with Urgent priority (risk score \u2265 80)",
    },
    {
      key: "notify_kev",
      label: "Known Exploited (KEV)",
      description:
        "New vulnerabilities listed in CISA's Known Exploited Vulnerabilities catalog",
    },
    {
      key: "notify_all_new",
      label: "All New",
      description: "Any vulnerabilities new since a container's previous scan",
    },
    {
      key: "notify_digest",
      label: "Daily Digest",
      description:
        "Scheduled daily summary of all containers, vulnerability counts, and available image updates",
    },
    {
      key: "notify_eol",
      label: "EOL Distro",
      description: "Container found running on an end-of-life OS distribution",
    },
    {
      key: "notify_scan_failure",
      label: "Scan Failures",
      description:
        "A vulnerability scan failed (Grype error, Docker issue, etc.)",
    },
  ];
</script>

<div class="space-y-8">
  <div>
    <h3 class="text-lg font-medium">Notifications</h3>
    <p class="text-sm text-muted-foreground">
      Configure notification channels to receive alerts about vulnerabilities,
      scan failures, and daily digests via 80+ services.
    </p>
  </div>

  {#if loading}
    <div class="flex items-center justify-center p-12 text-muted-foreground">
      <Loader2 class="h-6 w-6 animate-spin mr-2" />
      Loading...
    </div>
  {:else}
    <!-- Notification Channels -->
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <h4 class="text-md font-medium">Channels</h4>
        <Button
          variant="outline"
          size="sm"
          onclick={() => (showAddForm = !showAddForm)}
        >
          <Plus class="mr-1 h-4 w-4" />
          Add Channel
        </Button>
      </div>

      {#if showAddForm}
        <Card.Root>
          <Card.Header>
            <Card.Title class="text-sm">New Notification Channel</Card.Title>
          </Card.Header>
          <Card.Content class="space-y-4">
            <div class="space-y-2 max-w-md">
              <Label for="new-name">Name</Label>
              <Input
                id="new-name"
                placeholder="e.g. My Slack"
                bind:value={newName}
              />
            </div>
            <div class="space-y-2 max-w-lg">
              <Label for="new-url">Apprise URL</Label>
              <Input
                id="new-url"
                placeholder="e.g. slack://TokenA/TokenB/TokenC"
                bind:value={newUrl}
              />
              <p class="text-xs text-muted-foreground">
                DockGuard will make outbound HTTP requests to the host specified
                in this URL. Only add URLs for services you trust.
              </p>
            </div>

            <Collapsible.Root>
              <Collapsible.Trigger
                class="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                <ChevronDown class="h-3 w-3" />
                URL Format Examples
              </Collapsible.Trigger>
              <Collapsible.Content>
                <div
                  class="mt-2 rounded-md border bg-muted/50 p-3 text-xs space-y-1 font-mono"
                >
                  <p><strong>Slack:</strong> slack://TokenA/TokenB/TokenC</p>
                  <p>
                    <strong>Discord:</strong> discord://WebhookID/WebhookToken
                  </p>
                  <p><strong>Pushover:</strong> pover://user@token</p>
                  <p><strong>Email:</strong> mailto://user:pass@gmail.com</p>
                  <p><strong>Gotify:</strong> gotify://host/token</p>
                  <p><strong>ntfy:</strong> ntfy://topic</p>
                  <p class="pt-1 font-sans">
                    <a
                      href="https://github.com/caronc/apprise/wiki"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="text-primary underline inline-flex items-center gap-1"
                    >
                      Full Apprise wiki (80+ services)
                      <ExternalLink class="h-3 w-3" />
                    </a>
                  </p>
                </div>
              </Collapsible.Content>
            </Collapsible.Root>

            {#if newError}
              <p class="text-sm text-destructive">{newError}</p>
            {/if}

            <div class="flex gap-2">
              <Button size="sm" disabled={creating} onclick={handleCreate}>
                {#if creating}
                  <Loader2 class="mr-1 h-4 w-4 animate-spin" />
                {/if}
                Create
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onclick={() => {
                  showAddForm = false;
                  newError = null;
                }}
              >
                Cancel
              </Button>
            </div>
          </Card.Content>
        </Card.Root>
      {/if}

      {#if notifications.channels.length === 0}
        <Card.Root>
          <Card.Content class="py-8 text-center text-muted-foreground">
            No notification channels configured. Add one to start receiving
            alerts.
          </Card.Content>
        </Card.Root>
      {/if}

      {#each notifications.channels as channel (channel.id)}
        <Card.Root class={channel.enabled ? "" : "opacity-60"}>
          <Card.Header>
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <Card.Title class="text-sm">{channel.name}</Card.Title>
                {#if !channel.enabled}
                  <Badge variant="outline" class="text-xs">Disabled</Badge>
                {/if}
              </div>
              <div class="flex items-center gap-2">
                <Label
                  for="enabled-{channel.id}"
                  class="text-xs text-muted-foreground">Enabled</Label
                >
                <Switch
                  id="enabled-{channel.id}"
                  checked={channel.enabled}
                  onCheckedChange={(v) => handleToggle(channel, "enabled", v)}
                  disabled={savingId === channel.id}
                />
              </div>
            </div>
          </Card.Header>
          <Card.Content class="space-y-4">
            <div>
              <p class="text-xs text-muted-foreground mb-1">Apprise URL</p>
              <code
                class="text-xs bg-muted px-2 py-1 rounded font-mono break-all"
                >{channel.apprise_url}</code
              >
              {#if (channel.body_maxlen ?? 32768) < 32768}
                <p class="text-xs text-muted-foreground mt-1">
                  Max message size: {(
                    channel.body_maxlen ?? 32768
                  ).toLocaleString()} characters — large notifications will be condensed
                  to fit.
                </p>
              {/if}
            </div>

            <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {#each toggleFields as tf (tf.key)}
                <div class="flex items-start gap-2">
                  <Switch
                    id="{tf.key}-{channel.id}"
                    checked={channel[tf.key] as boolean}
                    onCheckedChange={(v) => handleToggle(channel, tf.key, v)}
                    disabled={savingId === channel.id || !channel.enabled}
                    class="mt-0.5"
                  />
                  <div>
                    <Label
                      for="{tf.key}-{channel.id}"
                      class="text-xs font-medium">{tf.label}</Label
                    >
                    <p class="text-xs text-muted-foreground">
                      {tf.description}
                    </p>
                  </div>
                </div>
              {/each}
            </div>

            <div class="flex items-center gap-2 pt-2">
              <Button
                variant="outline"
                size="sm"
                disabled={testingId === channel.id}
                onclick={() => handleTest(channel.id)}
              >
                {#if testingId === channel.id}
                  <Loader2 class="mr-1 h-3 w-3 animate-spin" />
                {:else}
                  <Send class="mr-1 h-3 w-3" />
                {/if}
                Test
              </Button>

              <AlertDialog.Root
                open={deleteConfirmId === channel.id}
                onOpenChange={(open) => {
                  if (!open) deleteConfirmId = null;
                }}
              >
                <AlertDialog.Trigger>
                  {#snippet child({ props })}
                    <Button
                      variant="ghost"
                      size="sm"
                      class="text-destructive hover:text-destructive"
                      {...props}
                      onclick={() => (deleteConfirmId = channel.id)}
                    >
                      <Trash2 class="mr-1 h-3 w-3" />
                      Delete
                    </Button>
                  {/snippet}
                </AlertDialog.Trigger>
                <AlertDialog.Content>
                  <AlertDialog.Header>
                    <AlertDialog.Title>Delete Channel</AlertDialog.Title>
                    <AlertDialog.Description>
                      Are you sure you want to delete "{channel.name}"? This
                      will also remove all associated notification logs.
                    </AlertDialog.Description>
                  </AlertDialog.Header>
                  <AlertDialog.Footer>
                    <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
                    <AlertDialog.Action
                      onclick={() => handleDelete(channel.id)}
                    >
                      Delete
                    </AlertDialog.Action>
                  </AlertDialog.Footer>
                </AlertDialog.Content>
              </AlertDialog.Root>

              {#if testMessage && testMessage.id === channel.id}
                <span
                  class="text-xs {testMessage.type === 'success'
                    ? 'text-green-600 dark:text-green-500'
                    : 'text-destructive'}"
                >
                  {testMessage.text}
                </span>
              {/if}
            </div>
          </Card.Content>
        </Card.Root>
      {/each}
    </div>

    <!-- Notification Log -->
    <div class="space-y-4">
      <h4 class="text-md font-medium">Notification Log</h4>

      {#if notifications.log.length === 0}
        <Card.Root>
          <Card.Content class="py-8 text-center text-muted-foreground">
            No notifications sent yet.
          </Card.Content>
        </Card.Root>
      {:else}
        <Card.Root>
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>Time</Table.Head>
                <Table.Head>Type</Table.Head>
                <Table.Head>Channel</Table.Head>
                <Table.Head>Title</Table.Head>
                <Table.Head>Status</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each notifications.log as entry (entry.id)}
                <Table.Row>
                  <Table.Cell
                    class="text-xs text-muted-foreground whitespace-nowrap"
                  >
                    {formatDate(entry.created_at)}
                  </Table.Cell>
                  <Table.Cell>
                    <Badge variant={typeVariant(entry.notification_type)}>
                      {typeLabel(entry.notification_type)}
                    </Badge>
                  </Table.Cell>
                  <Table.Cell class="text-sm">{entry.channel_name}</Table.Cell>
                  <Table.Cell class="text-sm max-w-xs truncate">
                    {entry.title}
                  </Table.Cell>
                  <Table.Cell>
                    {#if entry.status === "sent"}
                      <Badge variant="outline">Sent</Badge>
                    {:else}
                      <Badge
                        variant="destructive"
                        title={entry.error_message ?? ""}
                      >
                        Failed
                      </Badge>
                    {/if}
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        </Card.Root>

        {#if notifications.logTotal > 50}
          <Pagination.Root
            count={notifications.logTotal}
            perPage={50}
            bind:page={logPage}
          >
            {#snippet children({ pages, currentPage })}
              <Pagination.Content>
                <Pagination.Item><Pagination.Previous /></Pagination.Item>
                {#each pages as pageItem (pageItem.key)}
                  <Pagination.Item>
                    {#if pageItem.type === "page"}
                      <Pagination.Link
                        page={pageItem}
                        isActive={currentPage === pageItem.value}
                      />
                    {:else}
                      <Pagination.Ellipsis />
                    {/if}
                  </Pagination.Item>
                {/each}
                <Pagination.Item><Pagination.Next /></Pagination.Item>
              </Pagination.Content>
            {/snippet}
          </Pagination.Root>
        {/if}
      {/if}
    </div>
  {/if}
</div>
