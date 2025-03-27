import { maybeDownload } from "@zk-kit/artifacts"
import { tmpdir } from "node:os"

// consider merging this function to pse snark-artifacts in the future
// download precompiled circuit based on the merkleTreeDepth
export default async function maybeGetNoirArtifacts(merkleTreeDepth: number): Promise<string> {
    const BASE_URL = "https://github.com/hashcloak/snark-artifacts/blob/semaphore-noir/packages/semaphore-noir"
    const url = `${BASE_URL}/semaphore-noir-${merkleTreeDepth}.json?raw=true`

    const outputPath = `${tmpdir()}/semaphore-noir/${merkleTreeDepth}`
    const circuitPath = await maybeDownload(url, outputPath)

    return circuitPath
}
