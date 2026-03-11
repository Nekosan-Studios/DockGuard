import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ params, url, fetch }) => {
  const limit = url.searchParams.get("limit") ?? "100";
  const res = await fetch(
    `${API_URL}/db/table/${encodeURIComponent(params.table)}?limit=${encodeURIComponent(limit)}`
  );
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
