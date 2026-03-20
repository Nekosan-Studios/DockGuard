import js from "@eslint/js";
import ts from "typescript-eslint";
import svelte from "eslint-plugin-svelte";
import globals from "globals";

export default [
  js.configs.recommended,
  ...ts.configs.recommended,
  ...svelte.configs["flat/recommended"],
  {
    linterOptions: {
      // Treat stale/unused eslint-disable comments as errors
      reportUnusedDisableDirectives: "error",
    },
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
  },
  {
    files: ["**/*.svelte"],
    languageOptions: {
      parserOptions: { parser: ts.parser },
    },
  },
  // .svelte.ts/.svelte.js files are TypeScript modules, not Svelte components
  {
    files: ["**/*.svelte.ts", "**/*.svelte.js"],
    languageOptions: {
      parser: ts.parser,
    },
  },
  {
    rules: {
      // Too many valid uses of relative/external hrefs in existing code
      "svelte/no-navigation-without-resolve": "off",
    },
  },
  // Svelte 5 enforcement — prevent regressions to Svelte 4 patterns
  {
    rules: {
      // Ban svelte/store imports: use $state in .svelte.ts files instead
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "svelte/store",
              message:
                "Use $state in a .svelte.ts file instead of Svelte stores (Svelte 5).",
            },
          ],
        },
      ],
      // Prefer addEventListener-free, declarative event handling
      "svelte/no-add-event-listener": "error",
      // Enforce const for variables that are never reassigned
      "svelte/prefer-const": "error",
    },
  },
  // Shadcn UI components — do not modify these files (must come last to override above)
  {
    files: ["src/lib/components/ui/**"],
    rules: {
      "no-useless-assignment": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "svelte/no-navigation-without-resolve": "off",
      "svelte/prefer-const": "off",
    },
  },
  {
    ignores: ["build/", ".svelte-kit/", "dist/", "node_modules/", "coverage/"],
  },
];
