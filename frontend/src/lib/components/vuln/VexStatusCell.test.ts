import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import VexStatusCell from './VexStatusCell.svelte';

describe('VexStatusCell', () => {
    it('renders a dash for null/unknown statuses', () => {
        const { container } = render(VexStatusCell, { vexStatus: null });
        expect(container).toHaveTextContent('—');

        const { container: container2 } = render(VexStatusCell, { vexStatus: 'random_status' });
        expect(container2).toHaveTextContent('—');
    });

    it('renders emerald ShieldCheck for not_affected', () => {
        const { container } = render(VexStatusCell, { vexStatus: 'not_affected' });

        const svg = container.querySelector('svg');
        expect(svg).toBeInTheDocument();
        expect(svg?.className.baseVal).toContain('text-emerald-600');
    });

    it('renders red ShieldAlert for affected', () => {
        const { container } = render(VexStatusCell, { vexStatus: 'affected' });

        const svg = container.querySelector('svg');
        expect(svg).toBeInTheDocument();
        expect(svg?.className.baseVal).toContain('text-red-600');
    });

    it('renders amber Clock for under_investigation', () => {
        const { container } = render(VexStatusCell, { vexStatus: 'under_investigation' });

        const svg = container.querySelector('svg');
        expect(svg).toBeInTheDocument();
        expect(svg?.className.baseVal).toContain('text-amber-600');
    });

    it('renders blue ShieldCheck for fixed', () => {
        const { container } = render(VexStatusCell, { vexStatus: 'fixed' });

        const svg = container.querySelector('svg');
        expect(svg).toBeInTheDocument();
        expect(svg?.className.baseVal).toContain('text-blue-600');
    });

    it('builds tooltip string with statements when provided', async () => {
        const { container } = render(VexStatusCell, {
            vexStatus: 'not_affected',
            vexJustification: 'vulnerable_code_not_in_execute_path',
            vexStatement: 'We stripped the vulnerable binary entirely.'
        });

        // The constructed tooltip text is injected into the Tooltip.Content
        // Since it's lazy-rendered by Bits UI sometimes, we'll just check if it's in the document at all, or we can check the reactive derived string.
        // For testing library, we can query by text since the Svelte 5 derived calculates immediately.

        // Trigger hover on tooltip trigger so Content renders into document
        const trigger = container.querySelector('button');
        if (trigger) {
            import('@testing-library/svelte').then(({ fireEvent }) => {
                fireEvent.pointerEnter(trigger);
            });
        }

        // Use findByText which awaits the element to appear after the hover interaction
        expect(await screen.findByText(/Supplier declares: Not Affected/i)).toBeInTheDocument();
        expect(await screen.findByText(/vulnerable_code_not_in_execute_path/i)).toBeInTheDocument();
        expect(await screen.findByText(/We stripped the vulnerable binary/i)).toBeInTheDocument();
    });
});
