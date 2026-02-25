import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

const API_URL = env.API_URL ?? 'http://localhost:8765';

export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const res = await fetch(`${API_URL}/activity/recent`);
		if (!res.ok) return { activities: [] };
		const data = await res.json();
		return { activities: data.activities ?? [] };
	} catch {
		return { activities: [] };
	}
};
