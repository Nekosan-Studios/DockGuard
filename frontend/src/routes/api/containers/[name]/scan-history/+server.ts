import { env } from "$env/dynamic/private";
import type { RequestHandler } from "@sveltejs/kit";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ params, url, fetch }) => {
  const name = params.name ?? "";
  const searchParams = new URLSearchParams();
  for (const [k, v] of url.searchParams.entries()) {
    searchParams.set(k, v);
  }
  const res = await fetch(
    `${API_URL}/containers/${encodeURIComponent(name)}/scan-history?${searchParams}`
  );
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
