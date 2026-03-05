import { env } from '$env/dynamic/private';
import type { RequestHandler } from '@sveltejs/kit';

const API_URL = env.API_URL ?? 'http://localhost:8765';

/**
 * Proxy for GET /vulnerabilities (cross-container, paginated).
 * Called client-side by the vulnerabilities page for subsequent infinite-scroll pages.
 */
export const GET: RequestHandler = async ({ url, fetch }) => {
    const params = new URLSearchParams();
    for (const [k, v] of url.searchParams.entries()) {
        params.set(k, v);
    }
    const res = await fetch(`${API_URL}/vulnerabilities?${params}`);
    return new Response(res.body, {
        status: res.status,
        headers: { 'content-type': 'application/json' }
    });
};
