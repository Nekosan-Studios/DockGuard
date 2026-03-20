import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const GET: RequestHandler = async ({ fetch }) => {
  const res = await fetch(`${API_URL}/notifications/channels`);
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};

export const POST: RequestHandler = async ({ request, fetch }) => {
  const body = await request.text();
  const res = await fetch(`${API_URL}/notifications/channels`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
