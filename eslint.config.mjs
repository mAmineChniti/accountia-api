import tseslint from 'typescript-eslint';
import parser from '@typescript-eslint/parser';
import eslintNestJs from '@darraghor/eslint-plugin-nestjs-typed';
import globals from 'globals';
import { defineConfig, globalIgnores } from 'eslint/config';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import unicornPlugin from 'eslint-plugin-unicorn';

export default defineConfig(
  tseslint.configs.recommendedTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  eslintPluginPrettierRecommended,
  unicornPlugin.configs.all,
  [
    globalIgnores([
      'dist/**',
      'node_modules/**',
      'coverage/**',
      'jest.config.js',
    ]),
    {
      files: ['eslint.config.mjs', '*.config.mjs', '*.config.js'],
      languageOptions: {
        parser: 'espree',
        parserOptions: {
          ecmaVersion: 'latest',
          sourceType: 'module',
        },
      },
    },
    {
      files: ['**/*.{ts,js,mjs,cjs}'],
      rules: {
        '@typescript-eslint/array-type': 'off',
        '@typescript-eslint/consistent-type-definitions': 'off',
        '@typescript-eslint/no-deprecated': 'warn',
        '@typescript-eslint/consistent-type-imports': [
          'warn',
          { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
        ],
        '@typescript-eslint/no-unused-vars': [
          'warn',
          { argsIgnorePattern: '^_' },
        ],
        '@typescript-eslint/no-misused-promises': [
          'error',
          { checksVoidReturn: { attributes: false } },
        ],
        'unicorn/no-keyword-prefix': 'off',
        'unicorn/prevent-abbreviations': 'off',
      },
    },
    {
      linterOptions: {
        reportUnusedDisableDirectives: true,
      },
      languageOptions: {
        globals: {
          ...globals.node,
          ...globals.jest,
        },
        parser,
        ecmaVersion: 'latest',
        sourceType: 'module',
        parserOptions: {
          projectService: true,
          tsconfigRootDir: import.meta.dirname,
        },
      },
    },
    {
      files: ['test/**/*.ts'],
      rules: {
        '@typescript-eslint/no-unsafe-argument': 'off',
        '@typescript-eslint/no-unsafe-assignment': 'off',
        '@typescript-eslint/no-unsafe-member-access': 'off',
        '@typescript-eslint/no-unsafe-call': 'off',
        '@typescript-eslint/no-unsafe-return': 'off',
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/unbound-method': 'off',
        '@typescript-eslint/no-unused-vars': 'warn',
        'unicorn/no-null': 'off',
        'unicorn/no-thenable': 'off',
        'unicorn/consistent-function-scoping': 'off',
        'unicorn/numeric-separators-style': 'off',
        'unicorn/no-immediate-mutation': 'off',
        'unicorn/no-useless-undefined': 'off',
      },
    },
    eslintNestJs.configs.flatRecommended,
  ]
);
