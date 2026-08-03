import { readFile } from "node:fs/promises"

import { describe, expect, test } from "bun:test"

const workflowUrl = new URL("../../.github/workflows/publish.yaml", import.meta.url)

describe("npm release workflow", () => {
    test("publishes GitHub releases from a hosted runner with trusted publishing", async () => {
        const workflow = await readFile(workflowUrl, "utf8")

        expect(workflow).toContain("release:\n        types: [published]")
        expect(workflow).toContain("runs-on: ubuntu-latest")
        expect(workflow).toContain("RELEASE_TAG: ${{ github.event.release.tag_name }}")
        expect(workflow).toContain("id-token: write")
        expect(workflow).toContain("--registry https://registry.npmjs.org/")
        expect(workflow).not.toContain("NODE_AUTH_TOKEN")
        expect(workflow).not.toContain("NPM_TOKEN")
        expect(workflow).not.toContain("npm.manaf.ch")
    })
})
