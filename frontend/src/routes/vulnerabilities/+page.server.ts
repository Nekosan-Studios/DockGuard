import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

const API_URL = env.API_URL ?? 'http://localhost:8765';

export const load: PageServerLoad = async ({ fetch, url }) => {
    const report = url.searchParams.get('report') || 'critical';

    const res = await fetch(`${API_URL}/vulnerabilities?report=${encodeURIComponent(report)}`).catch(() => null);

    if (!res?.ok) {
        return {
            report,
            vulnerabilities: [],
            count: 0
        };
    }

    const data = await res.json();

    return {
        report: data.report,
        vulnerabilities: data.vulnerabilities ?? [],
        count: data.count ?? 0
    };
};
