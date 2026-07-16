import type { Metadata } from "next"
import type { ReactNode } from "react"
import { RootProvider } from "fumadocs-ui/provider/next"
import "./global.css"

export const metadata: Metadata = {
    title: {
        default: "modernssh",
        template: "%s — modernssh",
    },
    description: "A typed, ESM-native SSH client and server library for Node.js",
}

export default function RootLayout({ children }: { children: ReactNode }) {
    return (
        <html lang="en" suppressHydrationWarning>
            <body className="flex min-h-screen flex-col">
                <RootProvider>{children}</RootProvider>
            </body>
        </html>
    )
}
