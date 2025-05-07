import { spawn } from "child_process"
import { Project, maybeGetBatchVkPath } from "@zk-kit/artifacts"

/**
 * Verifies a batch proof of multiple Semaphore Noir proofs batched together
 *
 * @param proofPath Path to BatchProof
 * @param vkPath (Optional) Path to verification key. If verifying with keccak = true, this vk must have also been generated with the flag
 * @param keccak Whether verification should take the keccak flag into account
 * @returns whether the batch proof is valid or not
 */
export default async function verifyBatchProof(proofPath: string, vkPath?: string, keccak?: boolean): Promise<boolean> {
    const finalVkPath = vkPath ?? (await maybeGetBatchVkPath(Project.SEMAPHORE_NOIR))

    return new Promise((resolve) => {
        const verifyArgs = ["verify", "--scheme", "ultra_honk", "-k", finalVkPath, "-p", proofPath]
        if (keccak) {
            verifyArgs.push("--oracle_hash", "keccak")
        }

        const bbVerifyProcess = spawn("bb", verifyArgs, { stdio: "inherit" })

        bbVerifyProcess.on("close", (code: number) => {
            resolve(code === 0)
        })
    })
}
