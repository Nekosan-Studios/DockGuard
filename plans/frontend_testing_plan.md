# Frontend Unit Testing Strategy (SvelteKit)

The user asked: 
> *Are there standard ways to do this with Svelte/Typescript, etc that makes up our frontend?*

## Introduction
Yes! The standard, officially recommended way to unit test Svelte and SvelteKit applications is using **Vitest** in combination with the **Svelte Testing Library** (`@testing-library/svelte`).

Because SvelteKit utilizes Vite as its bundler under the hood, Vitest is a perfect native fit. It runs extremely fast, shares your existing `vite.config.ts`, and perfectly parses Svelte and TypeScript files out of the box without complex Webpack or Jest configurations.

## The Standard Stack
1. **Vitest**: The testing framework itself (the test runner, assertions like `expect()`, and mocking like `vi.fn()`).
2. **@testing-library/svelte**: Provides utilities to mount Svelte components in a simulated DOM (`jsdom` or `happy-dom`) and query them exactly how a user would interact with them (e.g., "find the button with text 'Scan' and click it").
3. **jsdom**: A pure JavaScript implementation of the DOM so components can be rendered in a fast Node.js CLI environment instead of launching a full headless chromium browser (which is what E2E frameworks like Playwright do).

## What We Should Test
Svelte testing generally falls into two categories for unit tests:

### 1. Utility Functions (Standard TDD)
Testing pure TypeScript logic that doesn't interact with the DOM, such as API helpers, date formatters, or data parsing logic.
*Example:* Testing that `formatDate(new Date())` correctly outputs a human-readable string.

### 2. Component Testing (DOM Interaction)
Mounting a `.svelte` file and asserting its behavior.
*Example:* Mounting the `VulnerabilityBadge.svelte` component.
- Passing `severity="Critical"` as a prop.
- Asserting over the DOM that the component successfully renders `<span class="bg-red-500">Critical</span>`.

## Proposed Implementation Steps
If you want to proceed with introducing this, we can take the following steps to configure the test runner:

1. **Install Dependencies:**
   ```bash
   cd frontend
   npm install -D vitest @testing-library/svelte @testing-library/jest-dom jsdom
   ```

2. **Configure Vitest (`vitest.config.ts`):**
   Create a test configuration that extends the existing Vite config and sets the test environment to `jsdom`.

3. **Create a Test Setup File:**
   Inject `@testing-library/jest-dom` matchers (like `.toBeInTheDocument()`) globally so they are available in every test.

4. **Add an NPM Script:**
   Add `"test:unit": "vitest"` to `frontend/package.json` so you can easily run tests via `npm run test:unit`.

5. **Write an Initial Test:**
   Create a sample test to prove the runner works, perhaps for a utility function or a simple UI component.

---
**Does this approach sound like what you are looking for? If so, we can proceed with installing Vitest and writing our first frontend unit test!**
