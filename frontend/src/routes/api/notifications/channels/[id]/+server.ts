import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const PATCH: RequestHandler = async ({ params, request, fetch }) => {
  const body = await request.text();
  const res = await fetch(`${API_URL}/notifications/channels/${params.id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body,
  });
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};

export const DELETE: RequestHandler = async ({ params, fetch }) => {
  const res = await fetch(`${API_URL}/notifications/channels/${params.id}`, {
    method: "DELETE",
  });
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
