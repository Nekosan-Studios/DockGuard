import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

const API_URL = env.API_URL ?? 'http://localhost:8765';

export const load: PageServerLoad = async ({ fetch }) => {
    const [tasksRes, scheduledRes] = await Promise.all([
        fetch(`${API_URL}/tasks?limit=100`).catch(() => null),
        fetch(`${API_URL}/tasks/scheduled`).catch(() => null)
    ]);

    const tasksData = tasksRes?.ok ? await tasksRes.json() : { tasks: [] };
    const scheduledData = scheduledRes?.ok ? await scheduledRes.json() : { jobs: [] };

    return {
        tasks: tasksData.tasks ?? [],
        scheduledJobs: scheduledData.jobs ?? [],
        apiError: !tasksRes?.ok,
    };
};
