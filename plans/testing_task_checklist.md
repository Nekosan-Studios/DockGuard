# Expanding Frontend Test Coverage

## Utilities
- [x] Write tests for `frontend/src/lib/components/vuln/utils.ts` (`cvssTooltip`, `epssTooltip`, `toUtcDate`, etc.)

## Vulnerability Components (`src/lib/components/vuln/`)
- [x] Write tests for `CvssCell.svelte` (renders correct colors/scores)
- [x] Write tests for `EpssCell.svelte` (renders correct colors/scores)
- [x] Write tests for `KevCell.svelte` (renders KEV badge when true, empty otherwise)
- [x] Write tests for `VexStatusCell.svelte` (renders VEX status icons correctly)

## Layout & Global Components (`src/lib/components/`)
- [x] Write tests for `app-sidebar.svelte` (navigation links render correctly)
- [x] Write tests for `mode-toggle.svelte` (renders light/dark theme toggle button)

## Verification
- [x] Run `npm run test:unit -- --coverage` and verify lines coverage improves significantly.
