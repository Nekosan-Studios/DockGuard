import { env } from "$env/dynamic/private";
import type { PageServerLoad } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const load: PageServerLoad = async ({ fetch }) => {
  const summaryRes = await fetch(`${API_URL}/dashboard/summary`).catch(
    () => null
  );

  const summaryOk = summaryRes?.ok;
  const summary = summaryOk
    ? await summaryRes!.json()
    : {
        running_containers: null,
        unique_running_images: null,
        critical_count: null,
        kev_count: null,
        urgent_count: null,
        new_findings: null,
        trend: [],
        now_point: null,
        docker_connected: false,
        grype_version: null,
        db_schema: null,
        db_built: null,
        last_db_checked_at: null,
        active_tasks: 0,
        queued_tasks: 0,
        eol_count: 0,
      };

  return { summary, apiError: !summaryOk };
};
