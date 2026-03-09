import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import SeverityCell from './SeverityCell.svelte';

describe('SeverityCell', () => {
    it('renders the severity text correctly', () => {
        const { container } = render(SeverityCell, { severity: 'Critical' });

        const badge = screen.getByText('Critical');
        expect(badge).toBeInTheDocument();

        // It should contain the classes mapped from utils.ts for Critical
        expect(badge.className).toContain('bg-red-100');
        expect(badge.className).toContain('text-red-800');
    });

    it('falls back to Unknown class when an invalid severity is passed', () => {
        render(SeverityCell, { severity: 'GarbageSeverity' });

        const badge = screen.getByText('GarbageSeverity');
        expect(badge).toBeInTheDocument();

        // It should contain the default classes mapped from utils.ts for Unknown
        expect(badge.className).toContain('text-gray-500');
    });
});
