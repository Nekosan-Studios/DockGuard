import { env } from "$env/dynamic/private";
import type { PageServerLoad } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const load: PageServerLoad = async ({ fetch }) => {
  try {
    const res = await fetch(`${API_URL}/containers/running`);
    if (!res.ok) return { containers: [], apiError: true };
    const data = await res.json();
    return { containers: data.containers ?? [], apiError: false };
  } catch {
    return { containers: [], apiError: true };
  }
};
