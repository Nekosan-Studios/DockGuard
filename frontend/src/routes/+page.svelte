<script>
  import { onMount } from 'svelte';
  import { api } from '$lib/api.js';
  import StatCard from '$lib/components/StatCard.svelte';
  import SeverityBadge from '$lib/components/SeverityBadge.svelte';

  let totalCount = $state(null);
  let criticalRunning = $state(null);
  let loadingCount = $state(true);
  let loadingRunning = $state(true);
  let errorCount = $state(null);
  let errorRunning = $state(null);

  onMount(async () => {
    // Fetch total vulnerability count
    api.getVulnerabilityCount()
      .then((data) => { totalCount = data.total_vulnerability_count; })
      .catch((err) => { errorCount = err.message; })
      .finally(() => { loadingCount = false; });

    // Fetch critical vulnerabilities in running containers
    api.getCriticalRunning()
      .then((data) => { criticalRunning = data; })
      .catch((err) => { errorRunning = err.message; })
      .finally(() => { loadingRunning = false; });
  });
</script>

<svelte:head>
  <title>Dashboard — DockerSecurityWatch</title>
</svelte:head>

<h1 class="page-title">Dashboard</h1>

<!-- Stat Cards -->
<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px;">
  <StatCard
    label="Total Vulnerabilities"
    value={errorCount ? 'Error' : (loadingCount ? '…' : totalCount)}
    subtitle="across all scanned images"
    loading={loadingCount}
  />
  <StatCard
    label="Critical (Running)"
    value={errorRunning ? 'Error' : (loadingRunning ? '…' : (criticalRunning?.count ?? 0))}
    subtitle="in live containers"
    loading={loadingRunning}
  />
</div>

<!-- Critical vulnerabilities table -->
<div style="display: flex; align-items: center; margin-bottom: 12px;">
  <h2 class="section-title" style="margin: 0;">Critical Vulnerabilities in Running Containers</h2>
  {#if !loadingRunning && criticalRunning}
    <span class="count-chip">{criticalRunning.count}</span>
  {/if}
</div>

{#if loadingRunning}
  <div class="loading-msg">Loading…</div>
{:else if errorRunning}
  <div class="error-msg">{errorRunning}</div>
{:else if !criticalRunning?.vulnerabilities?.length}
  <div class="table-wrapper">
    <div class="empty-state">No critical vulnerabilities found in running containers.</div>
  </div>
{:else}
  <div class="table-wrapper">
    <table class="data-table">
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Severity</th>
          <th>Package</th>
          <th>Version</th>
          <th>Fixed In</th>
          <th>CVSS</th>
          <th>KEV</th>
        </tr>
      </thead>
      <tbody>
        {#each criticalRunning.vulnerabilities as vuln}
          <tr>
            <td>
              {#if vuln.urls}
                <a
                  href={vuln.urls.split(',')[0].trim()}
                  target="_blank"
                  rel="noopener noreferrer"
                  style="color: var(--accent); text-decoration: none; font-family: monospace; font-size: 12px;"
                >
                  {vuln.vuln_id}
                </a>
              {:else}
                <span style="font-family: monospace; font-size: 12px;">{vuln.vuln_id}</span>
              {/if}
            </td>
            <td><SeverityBadge severity={vuln.severity} /></td>
            <td style="font-family: monospace; font-size: 12px;">{vuln.package_name}</td>
            <td style="font-family: monospace; font-size: 12px; color: var(--muted);">{vuln.installed_version}</td>
            <td style="font-family: monospace; font-size: 12px; color: var(--muted);">
              {vuln.fixed_version ?? '—'}
            </td>
            <td>{vuln.cvss_base_score != null ? vuln.cvss_base_score.toFixed(1) : '—'}</td>
            <td>
              {#if vuln.is_kev}
                <span class="kev-check" title="Known Exploited Vulnerability">KEV</span>
              {:else}
                <span style="color: var(--muted);">—</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  {#if criticalRunning.running_images?.length}
    <div style="margin-top: 16px; font-size: 12px; color: var(--muted);">
      Scanned images:
      {#each criticalRunning.running_images as img, i}
        <span style="font-family: monospace;">{img}</span>{#if i < criticalRunning.running_images.length - 1}, {/if}
      {/each}
    </div>
  {/if}
{/if}
