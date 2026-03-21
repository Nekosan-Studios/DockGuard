import { env } from "$env/dynamic/private";
import type { PageServerLoad } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const load: PageServerLoad = async ({ fetch }) => {
  try {
    const res = await fetch(`${API_URL}/containers/running`);
    if (!res.ok) return { trackedImageCount: 0 };
    const data = await res.json();
    return { trackedImageCount: (data.containers ?? []).length };
  } catch (e) {
    console.warn("Failed to fetch container count for DB size estimate:", e);
    return { trackedImageCount: 0 };
  }
};
