import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ url, fetch }) => {
  const params = new URLSearchParams();
  for (const id of url.searchParams.getAll("task_ids")) {
    params.append("task_ids", id);
  }
  const res = await fetch(`${API_URL}/preview-scans/status?${params}`);
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
