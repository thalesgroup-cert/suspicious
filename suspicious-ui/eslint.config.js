import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";

export default [
  { ignores: ["dist/**", "node_modules/**", ".playwright/**", "src/bones/**", "public/**"] },

  js.configs.recommended,

  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tseslint.parser,
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // React Refresh: helps prevent incorrect exports during HMR
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],

      // Practical defaults
      "no-console": ["warn", { allow: ["warn", "error"] }],
      // Empty catch blocks are an intentional "ignore" idiom here.
      "no-empty": ["error", { allowEmptyCatch: true }],

      // react-hooks v7 bundles react-compiler rules that are strict on
      // existing manually-memoized code. Keep them visible as warnings rather
      // than blocking CI on a compiler-driven refactor. rules-of-hooks stays
      // an error (it catches real hook-order bugs).
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/preserve-manual-memoization": "warn",

      // New in eslint 10 recommended; fires on benign default-init patterns.
      "no-useless-assignment": "warn",

      // TypeScript resolves identifiers + unused symbols itself (tsc -b runs
      // separately in CI); the core JS rules misfire on type-only references.
      "no-undef": "off",
      "no-unused-vars": "off",
    },
  },

  // Node-context tooling — allow process, __dirname, etc.
  {
    files: [
      "**/*.config.{ts,js}",
      "e2e/**/*.{ts,tsx}",
      "src/test/**/*.{ts,tsx}",
    ],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
];
