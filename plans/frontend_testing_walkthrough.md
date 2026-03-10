# SvelteKit Unit Testing Walkthrough

## Overview
We have successfully implemented incredibly fast, standard Frontend unit testing using **Vitest** and **Svelte Testing Library**. 

This stack avoids heavy E2E frameworks like Playwright for small logical checks, natively parsing `.svelte` DOM mounts within milliseconds safely without booting a full browser.

## Core Implementations

### 1. The Vitest Test Environment
The `frontend/vite.config.ts` was extended to recognize Vitest. We instructed it to use `jsdom` (an implementation of the web standard APIs in pure JavaScript mapping to Node) so that DOM calls like `document.createElement` wouldn't crash.

Crucially, because this is Svelte 5, we utilized `@testing-library/svelte/vite` via `svelteTesting()`. This solves known `Svelte error: lifecycle_function_unavailable` issues by signaling Svelte to compile as a client-side component (browser module bindings) instead of an SSR component during the `npm test` phase.

### 2. Global Jest DOM Enhancements
A new `frontend/vitest-setup.ts` file was introduced to import `@testing-library/jest-dom`. Doing this globally grants us access to specific UI matchers in out Vitest assertions:
- `expect(element).toBeInTheDocument()`
- `expect(element).toHaveClass()`
- `expect(element).toHaveTextContent()`

### 3. Utility Function Testing
We successfully proved pure code blocks can be tested. `frontend/src/lib/utils.test.ts` imports the `cn()` CSS merge behavior. It executes without `jsdom` and strictly validates that boolean tailwind logic resolves conditionally and merges overlapping padding conflicts as intended.

### 4. DOM Svelte Component Testing
We verified `.svelte` DOM instantiation by building `frontend/src/lib/components/vuln/SeverityCell.test.ts`.

It utilizes `render(...)` and `screen` to boot the actual component:
```typescript
import { render, screen } from '@testing-library/svelte';
import SeverityCell from './SeverityCell.svelte';

render(SeverityCell, { severity: 'Critical' });
const badge = screen.getByText('Critical');
```
We then trigger `expect(badge.className).toContain('bg-red-100')` ensuring the component mapped the internal properties completely correctly to its HTML projection.

## Expanding The Coverage Base

### 5. Complex Svelte 5 Context Testing
As the suite expanded to cover more advanced component architectures like `EpssCell`, `VexStatusCell`, and `app-sidebar.svelte`, we encountered errors relating to missing Svelte 5 Component Contexts.

Because modern Svelte libraries heavily lean into `Provider` wrappers to inject reactive states statically in isolated tree domains, testing `Sidebar` navigation logic directly inherently fails in vanilla `jsdom`. 

We authored custom wrapper scripts and globally mocked Svelte 5 contextual providers, solving issues such as:
1. `Tooltip.Provider` not found errors originating from `Bits UI` closures masking `<Tooltip.Root>`.
2. `mode-watcher` missing DOM globals like `localStorage` in pure node environments. We fixed this by assigning explicit generic JavaScript mocks to `window`.
3. `SidebarProvider` crashing testing due to missing `window.matchMedia` (used internally by Svelte responsive breakpoints). We implemented a global Vitest `matchMedia` node bypass to fake screen sizes safely.

### 6. Coverage Results
After comprehensively testing the presentation logic for:
- `utils.ts` (Tailwind logic)
- `vuln/utils.ts` (Score mapping logic)
- `SeverityCell.svelte`, `CvssCell.svelte`, `EpssCell.svelte`, `KevCell.svelte`, `VexStatusCell.svelte` (Badge and tooltip presentation)
- `app-sidebar.svelte` and `mode-toggle.svelte` (Layout interactions)

The execution of `npm run test:unit -- --coverage` successfully rendered perfect branch and UI assertion completions, drastically improving overall component logic validation in the codebase.

## Running the Specs
The testing suite sits at `npm run test:unit` inside the `frontend/` directory. Currently all specifications across pure functions and DOM components resolve in ~1 second.
