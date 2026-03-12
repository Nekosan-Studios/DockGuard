import { env } from "$env/dynamic/private";
import type { PageServerLoad } from "./$types";

const API_URL = env.API_URL ?? "http://localhost:8765";

export const load: PageServerLoad = async ({ fetch, url }) => {
  const report = url.searchParams.get("report") || "critical";
  const new_hours = url.searchParams.get("new_hours") || "24";
  const hide_vex = url.searchParams.get("hide_vex") || "false";
  const sort_by = url.searchParams.get("sort_by") || "severity";
  const sort_dir = url.searchParams.get("sort_dir") || "asc";

  const params = new URLSearchParams({
    report,
    new_hours,
    hide_vex,
    sort_by,
    sort_dir,
    limit: "100",
    offset: "0",
  });

  const res = await fetch(`${API_URL}/vulnerabilities?${params}`).catch(
    () => null
  );

  if (!res?.ok) {
    return {
      report,
      sort_by,
      sort_dir,
      vulnerabilities: [],
      count: 0,
      total_count: 0,
      has_more: false,
      has_any_vex: false,
      eol_images: [] as { container_name: string; distro: string | null }[],
      apiError: true,
    };
  }

  const data = await res.json();

  return {
    report: data.report || report,
    sort_by,
    sort_dir,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    vulnerabilities: (data.vulnerabilities ?? []) as any[],
    count: (data.count ?? 0) as number,
    total_count: (data.total_count ?? 0) as number,
    total_instances: (data.total_instances ?? 0) as number,
    has_more: (data.has_more ?? false) as boolean,
    has_any_vex: (data.has_any_vex ?? false) as boolean,
    eol_images: (data.eol_images ?? []) as {
      container_name: string;
      distro: string | null;
    }[],
    apiError: false,
  };
};
