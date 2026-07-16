import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared"

export function baseOptions(): BaseLayoutProps {
    return {
        nav: {
            title: "modernssh",
        },
        links: [
            {
                text: "Getting started",
                url: "/getting-started",
                active: "nested-url",
            },
            {
                text: "Examples",
                url: "/examples",
                active: "nested-url",
            },
            {
                text: "API",
                url: "/api",
                active: "nested-url",
            },
        ],
        githubUrl: "https://github.com/bunkerch/node-ssh",
    }
}
