import { env } from "$env/dynamic/private";
import type { RequestHandler } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const POST: RequestHandler = async ({ params, fetch }) => {
  const res = await fetch(
    `${API_URL}/notifications/channels/${params.id}/test`,
    { method: "POST" }
  );
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
};
