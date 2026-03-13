import { env } from "$env/dynamic/private";
import type { PageServerLoad } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const load: PageServerLoad = async ({ fetch }) => {
  const [tasksRes, scheduledRes] = await Promise.all([
    fetch(`${API_URL}/tasks?limit=100`).catch(() => null),
    fetch(`${API_URL}/tasks/scheduled`).catch(() => null),
  ]);

  const tasksData = tasksRes?.ok ? await tasksRes.json() : { tasks: [] };
  const scheduledData = scheduledRes?.ok
    ? await scheduledRes.json()
    : { jobs: [] };

  const scheduledRows = (scheduledData.jobs ?? []).map(
    (job: {
      id: string;
      name: string;
      next_run_time: string | null;
      interval_seconds: number | null;
    }) => ({
      id: job.id,
      task_name: job.name,
      task_type: "scheduled",
      status: "scheduled",
      created_at: job.next_run_time,
      started_at: null,
      finished_at: null,
      error_message: null,
      result_details: job.interval_seconds
        ? `Every ${Math.floor(job.interval_seconds / 60)} minutes`
        : null,
    })
  );

  return {
    tasks: [...(tasksData.tasks ?? []), ...scheduledRows],
    apiError: !tasksRes?.ok,
  };
};
