import js from "@eslint/js";
import ts from "typescript-eslint";
import svelte from "eslint-plugin-svelte";
import globals from "globals";

export default [
  js.configs.recommended,
  ...ts.configs.recommended,
  ...svelte.configs["flat/recommended"],
  {
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
  // Shadcn UI components — do not modify these files
  {
    files: ["src/lib/components/ui/**"],
    rules: {
      "no-useless-assignment": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "svelte/no-navigation-without-resolve": "off",
    },
  },
  {
    rules: {
      // Too many valid uses of relative/external hrefs in existing code
      "svelte/no-navigation-without-resolve": "off",
    },
  },
  {
    ignores: ["build/", ".svelte-kit/", "dist/", "node_modules/", "coverage/"],
  },
];
