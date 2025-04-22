import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { Project, maybeGetNoirVk } from "@zk-kit/artifacts"
import { spawn } from "child_process"

/**
 * Verifies whether a Semahpore Noir proof is valid. Depending on the value of
 * SemaphoreNoirProof.merkleTreeDepth, a different circuit is used.
 * (In practice that value either equals the depth of the tree of the Identities group,
 * or the length of the merkle proof used in the proof generation.)
 *
 * @param proofPath The path to a Semaphore Noir proof file
 * @param merkleTreeDepth The merkleTreeDepth of the Noir circuit
 * @param noirVkPath The path to a Semaphore Noir Verification Key file
 * @returns True if the proof is valid, false otherwise.
 */
export default async function verifyNoirProof(
    proofPath: string,
    merkleTreeDepth: number,
    noirVkPath?: string
): Promise<boolean> {
    // console.time("verifyNoirProof-e2e");
    if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
    }

    // console.time("verifyNoirProof-maybeGetCompiledNoirCircuit");
    // If the Noir VK has not been passed, it will be automatically downloaded.
    try {
        noirVkPath ??= await maybeGetNoirVk(Project.SEMAPHORE_NOIR, merkleTreeDepth)
    } catch (err) {
        throw new Error(`Failed to download VK: ${(err as Error).message}`)
    }
    // console.timeEnd("verifyNoirProof-maybeGetCompiledNoirCircuit");

    // start bb_verify
    // console.time("verifyNoirProof-verify");
    let result = false
    const verifyArgs = ["verify", "--scheme", "ultra_honk", "-k", noirVkPath as string, "-p", proofPath]
    const bbVerifyProcess = spawn("bb", verifyArgs)
    bbVerifyProcess.stdout.on("data", (data) => {
        console.log(`bb_verify ${data}`)
    })
    bbVerifyProcess.stderr.on("data", (data) => {
        console.log(`bb_verify: ${data}`)
    })
    bbVerifyProcess.on("error", (err) => {
        throw new Error(`Failed to start process: ${err.message}`)
    })
    result = await new Promise((resolve) => {
        bbVerifyProcess.on("close", (code: number) => {
            if (code === 0) {
                resolve(true)
            } else {
                resolve(false)
            }
        })
    })
    // console.timeEnd("verifyNoirProof-verify");

    // console.timeEnd("verifyNoirProof-e2e");
    return result
}
