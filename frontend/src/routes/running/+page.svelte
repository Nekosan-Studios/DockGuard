<script>
  import { onMount } from 'svelte';
  import { api } from '$lib/api.js';
  import SeverityBadge from '$lib/components/SeverityBadge.svelte';

  let data = $state(null);
  let loading = $state(true);
  let error = $state(null);

  onMount(async () => {
    api.getCriticalRunning()
      .then((res) => { data = res; })
      .catch((err) => { error = err.message; })
      .finally(() => { loading = false; });
  });
</script>

<svelte:head>
  <title>Running Containers — DockerSecurityWatch</title>
</svelte:head>

<div style="display: flex; align-items: baseline; gap: 8px; margin-bottom: 24px;">
  <h1 class="page-title" style="margin: 0;">
    Critical Vulnerabilities — Running Containers
  </h1>
  {#if !loading && data}
    <span class="count-chip">{data.count}</span>
  {/if}
</div>

{#if loading}
  <div class="loading-msg">Loading…</div>

{:else if error}
  <div class="error-msg">{error}</div>

{:else if !data?.vulnerabilities?.length}
  <div class="table-wrapper">
    <div class="empty-state">
      {#if data?.running_images?.length === 0}
        No running containers found.
      {:else}
        No critical vulnerabilities found in running containers.
      {/if}
    </div>
  </div>

{:else}
  <!-- Running images summary -->
  {#if data.running_images?.length}
    <div style="margin-bottom: 16px; font-size: 12px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
      <span>Running:</span>
      {#each data.running_images as img}
        <span style="
          font-family: monospace;
          background-color: var(--card-bg);
          border: 1px solid var(--border);
          padding: 2px 8px;
          border-radius: 4px;
          color: var(--text);
        ">{img}</span>
      {/each}
    </div>
  {/if}

  <div class="table-wrapper">
    <table class="data-table">
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>EPSS</th>
          <th>KEV</th>
          <th>Package</th>
          <th>Version</th>
          <th>Fixed In</th>
        </tr>
      </thead>
      <tbody>
        {#each data.vulnerabilities as vuln}
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
            <td>
              {#if vuln.cvss_base_score != null}
                <span style="font-weight: 600; color: {vuln.cvss_base_score >= 9 ? '#ff7b7b' : vuln.cvss_base_score >= 7 ? '#ff9e40' : 'var(--text)'};">
                  {vuln.cvss_base_score.toFixed(1)}
                </span>
              {:else}
                <span style="color: var(--muted);">—</span>
              {/if}
            </td>
            <td>
              {#if vuln.epss_score != null}
                <span title="EPSS percentile: {vuln.epss_percentile != null ? (vuln.epss_percentile * 100).toFixed(1) + '%' : 'N/A'}">
                  {(vuln.epss_score * 100).toFixed(1)}%
                </span>
              {:else}
                <span style="color: var(--muted);">—</span>
              {/if}
            </td>
            <td>
              {#if vuln.is_kev}
                <span class="kev-check" title="CISA Known Exploited Vulnerability">✓</span>
              {:else}
                <span style="color: var(--muted);">—</span>
              {/if}
            </td>
            <td style="font-family: monospace; font-size: 12px;">{vuln.package_name}</td>
            <td style="font-family: monospace; font-size: 12px; color: var(--muted);">{vuln.installed_version}</td>
            <td style="font-family: monospace; font-size: 12px;">
              {#if vuln.fixed_version}
                <span style="color: #3fb950;">{vuln.fixed_version}</span>
              {:else}
                <span style="color: var(--muted);">—</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
