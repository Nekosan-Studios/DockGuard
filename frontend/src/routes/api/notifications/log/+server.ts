import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ url, fetch }) => {
  const page = url.searchParams.get("page") ?? "1";
  const page_size = url.searchParams.get("page_size") ?? "50";
  const res = await fetch(
    `${API_URL}/notifications/log?page=${page}&page_size=${page_size}`
  );
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
