import eslint from "@eslint/js"
import { defineConfig } from "eslint/config"
import tseslint from "typescript-eslint"
import stylistic from "@stylistic/eslint-plugin"

export default defineConfig(
    {
        ignores: ["dist/", ".next/", ".source/", "out/"],
    },
    eslint.configs.recommended,
    tseslint.configs.recommended,

    {
        plugins: {
            "@stylistic/ts": stylistic,
        },
    },
    tseslint.configs.stylistic,

    {
        files: ["src/**/*.ts"],
        languageOptions: {
            parserOptions: {
                projectService: true,
            },
        },
        rules: {
            "@typescript-eslint/no-misused-promises": [
                "error",
                {
                    checksVoidReturn: {
                        arguments: true,
                        attributes: false,
                        inheritedMethods: false,
                        properties: false,
                        returns: false,
                        variables: false,
                    },
                },
            ],
        },
    },

    {
        rules: {
            // Managed by typescript
            "no-undef": "off",

            // This one was disabled, if it's useful, enable it back.
            // "no-self-assign": "off",

            "no-empty": [
                "error",
                {
                    allowEmptyCatch: true,
                },
            ],

            // non-null assertion are useful when you know the
            // value, such as when in a branch. Also, it's not
            // always your false since this might be coming from
            // a library.
            "@typescript-eslint/no-non-null-assertion": "off",

            "@stylistic/ts/quotes": [
                "error",
                "double",
                {
                    avoidEscape: true,
                    allowTemplateLiterals: "always",
                },
            ],

            "no-restricted-syntax": [
                "error",
                {
                    selector:
                        "CallExpression[callee.type='MemberExpression'][callee.property.name=/^(on|once|addListener)$/] > ArrowFunctionExpression[async=true]",
                    message:
                        "EventEmitter does not await returned promises; use a synchronous listener with explicit rejection handling.",
                },
                {
                    selector:
                        "CallExpression[callee.type='MemberExpression'][callee.property.name=/^(on|once|addListener)$/] > FunctionExpression[async=true]",
                    message:
                        "EventEmitter does not await returned promises; use a synchronous listener with explicit rejection handling.",
                },
            ],
        },
    },
)
