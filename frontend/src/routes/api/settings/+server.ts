import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ fetch }) => {
  const res = await fetch(`${API_URL}/settings`);
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};

export const PATCH: RequestHandler = async ({ request, fetch }) => {
  const body = await request.text();
  const res = await fetch(`${API_URL}/settings`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body,
  });

  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
