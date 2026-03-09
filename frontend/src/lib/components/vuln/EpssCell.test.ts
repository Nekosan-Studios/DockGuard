import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import EpssCell from './EpssCell.svelte';

describe('EpssCell', () => {
    it('renders a dash when score is null', () => {
        const { container } = render(EpssCell, { score: null, percentile: null });
        expect(container).toHaveTextContent('—');
    });

    it('renders exactly formatted low scores (.toFixed(2)%) and applies correct classes', () => {
        const { container } = render(EpssCell, { score: 0.00512, percentile: 0.1 });

        // 0.00512 * 100 = 0.512, which is < 1, so it uses .toFixed(2)% -> "0.51%"
        const cellText = screen.getByText('0.51%');
        expect(cellText).toBeInTheDocument();

        // < 0.01 epssClass should be muted
        const cellNode = container.querySelector('td');
        expect(cellNode?.className).toContain('text-muted-foreground');
    });

    it('renders rounded middle scores (Math.round) and applies correct classes', () => {
        const { container } = render(EpssCell, { score: 0.256, percentile: 0.8 });

        // 0.256 * 100 = 25.6, which bounds 1 to 99.5, so rounded -> 26%
        const cellText = screen.getByText('26%');
        expect(cellText).toBeInTheDocument();

        // >= 0.1 epssClass should be orange
        const cellNode = container.querySelector('td');
        expect(cellNode?.className).toContain('text-orange-600');
    });

    it('renders exactly formatted high scores (.toFixed(2)%) and applies red class', () => {
        const { container } = render(EpssCell, { score: 0.998, percentile: 0.999 });

        // 0.998 * 100 = 99.8, which is >= 99.5, so .toFixed(2) -> 99.80%
        const cellText = screen.getByText('99.80%');
        expect(cellText).toBeInTheDocument();

        // >= 0.5 epssClass should be red
        const cellNode = container.querySelector('td');
        expect(cellNode?.className).toContain('text-red-700');
    });
});
