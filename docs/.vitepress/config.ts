import { defineConfig } from "vitepress"

const base = process.env.DOCS_BASE ?? "/"

export default defineConfig({
    lang: "en-US",
    title: "modernssh",
    titleTemplate: ":title — modernssh",
    description: "A typed, ESM-native SSH client and server library for Node.js",
    base,
    cleanUrls: true,
    lastUpdated: true,
    head: [
        ["meta", { name: "theme-color", content: "#2f6f5e" }],
        ["meta", { property: "og:type", content: "website" }],
        [
            "meta",
            {
                property: "og:description",
                content: "Typed, Promise-based SSH client and server APIs for Node.js",
            },
        ],
    ],
    themeConfig: {
        nav: [
            { text: "Guide", link: "/getting-started" },
            { text: "Examples", link: "/examples" },
            { text: "API", link: "/api/" },
            {
                text: "Protocol",
                items: [
                    { text: "Transport", link: "/transport" },
                    { text: "Interoperability", link: "/interoperability" },
                    { text: "Standards coverage", link: "/rfc-coverage" },
                ],
            },
        ],
        sidebar: [
            {
                text: "Start here",
                items: [
                    { text: "Introduction", link: "/" },
                    { text: "Getting started", link: "/getting-started" },
                    { text: "Examples", link: "/examples" },
                ],
            },
            {
                text: "Client and server",
                items: [
                    { text: "Authentication", link: "/authentication" },
                    { text: "Channels", link: "/channels" },
                    { text: "SFTP", link: "/sftp" },
                    { text: "Forwarding", link: "/forwarding" },
                    { text: "Packet tunnels", link: "/tunnels" },
                    { text: "Global requests", link: "/global-requests" },
                ],
            },
            {
                text: "Identity and trust",
                items: [
                    { text: "Known hosts", link: "/known-hosts" },
                    { text: "Agent protocol", link: "/agent-protocol" },
                    { text: "Public-key subsystem", link: "/public-key-subsystem" },
                    { text: "Key revocation lists", link: "/key-revocation-lists" },
                    { text: "Detached signatures", link: "/signatures" },
                ],
            },
            {
                text: "Protocol",
                items: [
                    { text: "Transport behavior", link: "/transport" },
                    { text: "Interoperability", link: "/interoperability" },
                    { text: "Standards coverage", link: "/rfc-coverage" },
                ],
            },
            {
                text: "API reference",
                collapsed: false,
                items: [
                    { text: "All exports", link: "/api/" },
                    { text: "Connections and servers", link: "/api/connections" },
                    { text: "Channels and forwarding", link: "/api/channels" },
                    { text: "Authentication", link: "/api/authentication" },
                    { text: "Agents", link: "/api/agents" },
                    { text: "SFTP", link: "/api/sftp" },
                    { text: "Keys and signatures", link: "/api/keys" },
                    { text: "Transport types", link: "/api/transport" },
                ],
            },
        ],
        outline: {
            level: [2, 3],
            label: "On this page",
        },
        search: {
            provider: "local",
            options: {
                detailedView: true,
            },
        },
        editLink: {
            pattern: "https://github.com/bunkerch/node-ssh/edit/master/docs/:path",
            text: "Edit this page on GitHub",
        },
        socialLinks: [{ icon: "github", link: "https://github.com/bunkerch/node-ssh" }],
        footer: {
            message: "Released under the MIT License.",
            copyright: "Copyright © 2026 bunkerch",
        },
    },
})
