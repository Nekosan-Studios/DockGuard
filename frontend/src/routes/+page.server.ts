import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

const API_URL = env.API_URL ?? 'http://localhost:8765';

export const load: PageServerLoad = async ({ fetch }) => {
	const [summaryRes, activityRes] = await Promise.all([
		fetch(`${API_URL}/dashboard/summary`).catch(() => null),
		fetch(`${API_URL}/activity/recent`).catch(() => null)
	]);

	const summary =
		summaryRes?.ok
			? await summaryRes.json()
			: { running_containers: null, images_scanned: null, critical_count: null, kev_count: null, new_vulns_24h: 0, trend: [], docker_connected: false, grype_version: null, db_version: null, db_built: null, last_db_checked_at: null };

	const activities = activityRes?.ok ? (await activityRes.json()).activities ?? [] : [];

	return { summary, activities };
};
