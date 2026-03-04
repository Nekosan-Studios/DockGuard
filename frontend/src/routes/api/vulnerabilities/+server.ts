import { env } from '$env/dynamic/private';
import type { RequestHandler } from './$types';

const API_URL = env.API_URL ?? 'http://localhost:8765';

export const GET: RequestHandler = async ({ url, fetch }) => {
	const imageRef = url.searchParams.get('image_ref');
	if (!imageRef) return new Response('Missing image_ref', { status: 400 });
	const severity = url.searchParams.get('severity');
	let backendUrl = `${API_URL}/images/vulnerabilities?image_ref=${encodeURIComponent(imageRef)}`;
	if (severity) backendUrl += `&severity=${encodeURIComponent(severity)}`;
	const res = await fetch(backendUrl);
	return new Response(res.body, {
		status: res.status,
		headers: { 'content-type': 'application/json' }
	});
};
