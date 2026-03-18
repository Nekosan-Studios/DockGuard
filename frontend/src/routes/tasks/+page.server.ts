import { env } from "$env/dynamic/private";
import type { PageServerLoad } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

function formatInterval(seconds: number): string {
  if (seconds % 3600 === 0) {
    const h = seconds / 3600;
    return `${h} ${h === 1 ? "hour" : "hours"}`;
  }
  if (seconds % 60 === 0) {
    const m = seconds / 60;
    return `${m} ${m === 1 ? "minute" : "minutes"}`;
  }
  return `${seconds} ${seconds === 1 ? "second" : "seconds"}`;
}

export const load: PageServerLoad = async ({ fetch, url }) => {
  const page = parseInt(url.searchParams.get("page") ?? "1", 10);

  const [tasksRes, scheduledRes] = await Promise.all([
    fetch(`${API_URL}/tasks?page=${page}&page_size=25`).catch(() => null),
    page === 1
      ? fetch(`${API_URL}/tasks/scheduled`).catch(() => null)
      : Promise.resolve(null),
  ]);

  const tasksData = tasksRes?.ok
    ? await tasksRes.json()
    : { tasks: [], total: 0 };
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
        ? `Every ${formatInterval(job.interval_seconds)}`
        : null,
    })
  );

  return {
    tasks: [...(tasksData.tasks ?? []), ...(page === 1 ? scheduledRows : [])],
    total: tasksData.total ?? 0,
    currentPage: page,
    apiError: !tasksRes?.ok,
  };
};
