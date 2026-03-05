export const SEVERITY_CLASSES: Record<string, string> = {
    Critical: "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800",
    High: "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800",
    Medium: "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-800",
    Low: "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800",
    Negligible: "bg-gray-100 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600",
    Unknown: "bg-gray-100 text-gray-500 border-gray-300 dark:bg-gray-800 dark:text-gray-500 dark:border-gray-600",
};

export function toUtcDate(iso: string): Date {
    return new Date(
        iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z",
    );
}

export function cvssTooltip(score: number): string {
    if (score >= 9.0) return "Critical severity";
    if (score >= 7.0) return "High severity";
    if (score >= 4.0) return "Medium severity";
    return "Low severity";
}

export function epssTooltip(score: number): string {
    if (score >= 0.5) return "Very high exploitation risk";
    if (score >= 0.1) return "Elevated exploitation risk";
    if (score >= 0.01) return "Moderate exploitation risk";
    return "Low exploitation risk";
}

export function cvssClass(score: number | null): string {
    if (score === null) return "text-muted-foreground";
    if (score >= 9.0) return "font-bold text-red-700 dark:text-red-400";
    if (score >= 7.0)
        return "font-semibold text-orange-600 dark:text-orange-400";
    if (score >= 4.0) return "text-amber-600 dark:text-amber-400";
    return "text-muted-foreground";
}

export function epssClass(score: number | null): string {
    if (score === null) return "text-muted-foreground";
    if (score >= 0.5) return "font-bold text-red-700 dark:text-red-400";
    if (score >= 0.1)
        return "font-semibold text-orange-600 dark:text-orange-400";
    if (score >= 0.01) return "text-amber-600 dark:text-amber-400";
    return "text-muted-foreground";
}
