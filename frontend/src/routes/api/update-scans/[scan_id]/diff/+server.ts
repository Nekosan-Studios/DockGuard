import { env } from "$env/dynamic/private";
import type { RequestHandler } from "@sveltejs/kit";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ params, fetch }) => {
  const scanId = params.scan_id ?? "";
  const res = await fetch(
    `${API_URL}/update-scans/${encodeURIComponent(scanId)}/diff`
  );
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
