import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

const API_URL = env.API_URL ?? 'http://localhost:8765';

export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const res = await fetch(`${API_URL}/db/tables`);
		if (!res.ok) return { tables: [] };
		const data = await res.json();
		return { tables: (data.tables ?? []) as string[] };
	} catch {
		return { tables: [] };
	}
};
