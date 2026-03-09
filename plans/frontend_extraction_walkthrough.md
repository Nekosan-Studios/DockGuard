# Frontend Component Extraction Update

## Completed Tasks

We have successfully refactored the sprawling, monolithic file structures inside the `frontend/src/routes/vulnerabilities` and `frontend/src/routes/containers` tables. 

### What was done
1. **Unified `VulnRow.svelte` component**: Instead of creating disparate components that reinvented how vulnerability data is displayed, we implemented a single `<VulnRow />` module.
   - It smartly processes `package` vs `vulnerability` payloads and scales effectively.
   - Distinct features between the Global Vulnerabilities and Container Sub-views were preserved using `showContainers` routing conditionals without bloat.
2. **Simplified `vulnerabilities/+page.svelte`**: Handed off 300+ lines of duplicated table rendering logic out of the main page scope directly to the instantiated unified `<VulnRow>`.
3. **Encapsulated Container Sub-View State**: Pulled out heavy and hard-to-maintain reactive `$state` arrays mapping the sub-views of `containers/+page.svelte` into a dedicated `<ContainerRow>` component that fully takes charge of internal visibility state.

## Current State & Next Steps

All `svelte-check` type checks correctly recognize the integration hooks across both modules. The build correctly propagates strict-mode props into `VulnRow`, like `hasVexData`.

We recommend navigating to the two views (`/containers` and `/vulnerabilities`) physically in your browser to verify:
- Container sub-view tables pop out and filter by Severity seamlessly.
- Vulnerabilities sub-tables properly collapse packages/fix versions.
- All column indicators like `VEX` and `CISA KEV` render correctly across both modules.
