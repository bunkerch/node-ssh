import { createMDX } from "fumadocs-mdx/next"

const configuredBase = process.env.DOCS_BASE
const basePath =
    configuredBase === undefined || configuredBase === "/"
        ? undefined
        : `/${configuredBase.replace(/^\/|\/$/gu, "")}`

/** @type {import("next").NextConfig} */
const config = {
    reactStrictMode: true,
    basePath,
    output: "standalone",
    allowedDevOrigins: ["*.dev.manaf.ch"],
    typescript: {
        tsconfigPath: "./tsconfig.docs.json",
    },
}

export default createMDX()(config)

import("@opennextjs/cloudflare").then((module) => module.initOpenNextCloudflareForDev())
