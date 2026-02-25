const BASE = '/api';

async function fetchJson(path) {
  const res = await fetch(BASE + path);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

export const api = {
  /**
   * GET /images/vulnerabilities?image_ref=<name:tag|sha256:...>
   * All vulnerabilities for the most recent scan of an image.
   */
  getVulnerabilities: (imageRef) =>
    fetchJson(`/images/vulnerabilities?image_ref=${encodeURIComponent(imageRef)}`),

  /**
   * GET /images/vulnerabilities/critical?image_ref=<name:tag|sha256:...>
   * Critical vulnerabilities for the most recent scan of an image.
   */
  getCriticalVulnerabilities: (imageRef) =>
    fetchJson(`/images/vulnerabilities/critical?image_ref=${encodeURIComponent(imageRef)}`),

  /**
   * GET /vulnerabilities/critical/running
   * Critical vulnerabilities across all currently running containers.
   * Returns { running_images: string[], count: number, vulnerabilities: Vulnerability[] }
   */
  getCriticalRunning: () =>
    fetchJson('/vulnerabilities/critical/running'),

  /**
   * GET /vulnerabilities/count
   * Total vulnerability count across the latest scan of every image.
   * Returns { total_vulnerability_count: number }
   */
  getVulnerabilityCount: () =>
    fetchJson('/vulnerabilities/count'),

  /**
   * GET /images/vulnerabilities/history?image=<repo|ref|digest>
   * Vulnerability counts over time for an image.
   * Returns { image: string, history: HistoryEntry[] }
   */
  getVulnerabilityHistory: (image) =>
    fetchJson(`/images/vulnerabilities/history?image=${encodeURIComponent(image)}`),
};
