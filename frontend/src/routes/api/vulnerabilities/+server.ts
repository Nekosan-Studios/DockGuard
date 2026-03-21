import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

/**
 * Proxy for GET /images/vulnerabilities (per-image, paginated).
 * Used by the containers sub-view to fetch per-severity vulnerability lists.
 * Forwards all query params (image_ref, severity, sort_by, sort_dir, limit, offset).
 */
export const GET: RequestHandler = async ({ url, fetch }) => {
  const imageRef = url.searchParams.get("image_ref");
  if (!imageRef) return new Response("Missing image_ref", { status: 400 });

  const params = new URLSearchParams();
  for (const [k, v] of url.searchParams.entries()) {
    params.set(k, v);
  }

  const t0 = performance.now();
  const res = await fetch(`${API_URL}/images/vulnerabilities?${params}`);
  const elapsed = performance.now() - t0;
  console.info(
    `[VulnLoad proxy /api/vulnerabilities] fetch: ${elapsed.toFixed(1)}ms status=${res.status}`
  );
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
