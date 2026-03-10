import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import CveLinkCell from './CveLinkCell.svelte';

describe('CveLinkCell', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('renders CVE ID as a link to NVD if no custom source is provided', () => {
        const { getByText } = render(CveLinkCell, {
            vulnId: 'CVE-2023-1234',
            dataSource: null,
            firstSeenAt: null
        });

        const link = getByText('CVE-2023-1234');
        expect(link.closest('a')).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2023-1234');
    });

    it('renders a custom data source link when provided', () => {
        const { getByText } = render(CveLinkCell, {
            vulnId: 'GHSA-abcd-1234',
            dataSource: 'https://github.com/advisories/GHSA-abcd-1234',
            firstSeenAt: null
        });

        const link = getByText('GHSA-abcd-1234');
        expect(link.closest('a')).toHaveAttribute('href', 'https://github.com/advisories/GHSA-abcd-1234');
    });

    it('does not display NEW badge for old vulnerabilities', () => {
        const pastDate = new Date();
        pastDate.setDate(pastDate.getDate() - 3); // 3 days ago

        const { queryByText } = render(CveLinkCell, {
            vulnId: 'CVE-2023-1234',
            firstSeenAt: pastDate.toISOString(),
            dataSource: null
        });

        expect(queryByText('NEW')).not.toBeInTheDocument();
    });

    it('displays NEW badge for vulnerabilities seen in the last 24 hours', () => {
        const recentDate = new Date();
        recentDate.setHours(recentDate.getHours() - 10); // 10 hours ago

        const { getByText } = render(CveLinkCell, {
            vulnId: 'CVE-2023-9999',
            firstSeenAt: recentDate.toISOString(),
            dataSource: null
        });

        expect(getByText('NEW')).toBeInTheDocument();
        expect(getByText('NEW')).toHaveClass('bg-emerald-100');
    });
});
