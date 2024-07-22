import js from "@eslint/js"
import ts from "typescript-eslint"

export default [
    {
        ignores: [
            "dist/",
            "node_modules/",
        ],
    },
    js.configs.recommended,
    ...ts.configs.strict,
    {
        rules: {
            quotes: [
                "error",
                "double",
                {
                    avoidEscape: true,
                    allowTemplateLiterals: true,
                },
            ],

            // typescript already verifies this
            "no-undef": "off",
            "no-constant-condition": "error",

            "@typescript-eslint/explicit-module-boundary-types": "off",
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-empty-function": "off",
            "@typescript-eslint/no-var-requires": "off",
            "@typescript-eslint/no-non-null-assertion": "off",

            "no-empty": [
                "error",
                {
                    allowEmptyCatch: true,
                },
            ],
        },
    },
]