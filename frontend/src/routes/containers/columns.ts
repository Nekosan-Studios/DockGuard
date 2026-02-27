import type { ColumnDef, SortingFn } from '@tanstack/table-core';
import { renderComponent, renderSnippet } from '$lib/components/ui/data-table/index.js';
import SortButton from './sort-button.svelte';
import type { Snippet } from 'svelte';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ContainerRow = {
    container_name: string;
    image_name: string;
    image_repository: string | null;
    image_digest: string | null;
    scan_id: number | null;
    scanned_at: string | null;
    vulns_by_severity: Record<string, number>;
    total: number;
    has_scan: boolean;
};

// ---------------------------------------------------------------------------
// Severity helpers (used by columns and cell snippets)
// ---------------------------------------------------------------------------

export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];

export const SEVERITY_CLASSES: Record<string, string> = {
    Critical:
        'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800',
    High: 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800',
    Medium:
        'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-800',
    Low: 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800',
    Negligible:
        'bg-gray-100 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
    Unknown:
        'bg-gray-100 text-gray-500 border-gray-300 dark:bg-gray-800 dark:text-gray-500 dark:border-gray-600'
};

export function activeSeverities(vulnsBySeverity: Record<string, number>) {
    return SEVERITY_ORDER.filter((s) => (vulnsBySeverity[s] ?? 0) > 0);
}

// ---------------------------------------------------------------------------
// Custom sorting: vulnerabilities by severity cascade
// ---------------------------------------------------------------------------

const vulnsSortingFn: SortingFn<ContainerRow> = (rowA, rowB) => {
    const a = rowA.original.vulns_by_severity;
    const b = rowB.original.vulns_by_severity;

    for (const sev of SEVERITY_ORDER) {
        const diff = (a[sev] ?? 0) - (b[sev] ?? 0);
        if (diff !== 0) return diff;
    }
    return 0;
};

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

export function createColumns(
    containerCell: Snippet<[{ row: ContainerRow }]>,
    vulnsCell: Snippet<[{ row: ContainerRow }]>,
    scannedCell: Snippet<[{ row: ContainerRow }]>
): ColumnDef<ContainerRow>[] {
    return [
        {
            accessorKey: 'container_name',
            header: ({ column }) =>
                renderComponent(SortButton, {
                    label: 'Container',
                    sortDirection: column.getIsSorted(),
                    onclick: column.getToggleSortingHandler()
                }),
            cell: ({ row }) => renderSnippet(containerCell, { row: row.original })
        },
        {
            id: 'vulns',
            accessorFn: (row) => row.vulns_by_severity['Critical'] ?? 0,
            sortingFn: vulnsSortingFn,
            header: ({ column }) =>
                renderComponent(SortButton, {
                    label: 'Vulnerabilities',
                    sortDirection: column.getIsSorted(),
                    onclick: column.getToggleSortingHandler()
                }),
            cell: ({ row }) => renderSnippet(vulnsCell, { row: row.original })
        },
        {
            accessorKey: 'total',
            header: ({ column }) =>
                renderComponent(SortButton, {
                    label: 'Total',
                    sortDirection: column.getIsSorted(),
                    onclick: column.getToggleSortingHandler()
                }),
            meta: { class: 'w-[70px] text-right' }
        },
        {
            accessorKey: 'scanned_at',
            header: ({ column }) =>
                renderComponent(SortButton, {
                    label: 'Last Scanned',
                    sortDirection: column.getIsSorted(),
                    onclick: column.getToggleSortingHandler()
                }),
            sortingFn: (rowA, rowB) => {
                const a = rowA.original.scanned_at;
                const b = rowB.original.scanned_at;
                // Nulls always sort last regardless of direction
                if (!a && !b) return 0;
                if (!a) return 1;
                if (!b) return -1;
                return a < b ? -1 : a > b ? 1 : 0;
            },
            sortUndefined: 'last',
            cell: ({ row }) => renderSnippet(scannedCell, { row: row.original }),
            meta: { class: 'w-[150px]' }
        }
    ];
}
