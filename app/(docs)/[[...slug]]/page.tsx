import type { Metadata } from "next"
import { notFound } from "next/navigation"
import { DocsBody, DocsPage, ViewOptionsPopover } from "fumadocs-ui/layouts/docs/page"
import { getMDXComponents } from "@/components/mdx"
import { source } from "@/lib/source"

interface PageProps {
    params: Promise<{ slug?: string[] }>
}

export default async function DocumentationPage({ params }: PageProps) {
    const { slug } = await params
    const page = source.getPage(slug ?? [])
    if (!page) notFound()

    const Content = page.data.body
    const isAPIReference = slug?.[0] === "api"

    return (
        <DocsPage full={isAPIReference} toc={isAPIReference ? [] : page.data.toc}>
            <ViewOptionsPopover
                githubUrl={`https://github.com/bunkerch/node-ssh/blob/master/docs/${page.path}`}
            />
            <DocsBody>
                <Content components={getMDXComponents()} />
            </DocsBody>
        </DocsPage>
    )
}

export function generateStaticParams(): { slug?: string[] }[] {
    return source.generateParams()
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
    const { slug } = await params
    const page = source.getPage(slug ?? [])
    if (!page) notFound()

    return {
        title:
            slug === undefined || slug.length === 0
                ? { absolute: page.data.title }
                : page.data.title,
        description: page.data.description,
    }
}
