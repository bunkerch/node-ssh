import { readFile } from "node:fs/promises"

import { describe, expect, test } from "bun:test"

const workflowUrl = new URL("../../.github/workflows/publish.yaml", import.meta.url)

describe("npm release workflow", () => {
    test("publishes GitHub releases from the self-hosted runner with token authentication", async () => {
        const workflow = await readFile(workflowUrl, "utf8")

        expect(workflow).toContain("release:\n        types: [published]")
        expect(workflow).toContain("runs-on: bunkerch-sysbox")
        expect(workflow).toContain("RELEASE_TAG: ${{ github.event.release.tag_name }}")
        expect(workflow).toContain("NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}")
        expect(workflow).toContain("--registry https://registry.npmjs.org/")
        expect(workflow).not.toContain("id-token: write")
        expect(workflow).not.toContain("npm.manaf.ch")
    })
})
