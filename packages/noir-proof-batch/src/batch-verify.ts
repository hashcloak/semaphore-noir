import { spawn } from "child_process"
import { Project, maybeGetBatchVkPath } from "@zk-kit/artifacts"

export default async function verifyNoirProof(proofPath: string, vkPath?: string, keccak?: boolean): Promise<boolean> {
    const finalVkPath = vkPath ?? (await maybeGetBatchVkPath(Project.SEMAPHORE_NOIR))

    return new Promise((resolve, reject) => {
        const verifyArgs = ["verify", "--scheme", "ultra_honk", "-k", finalVkPath, "-p", proofPath]
        if (keccak) {
            verifyArgs.push("--oracle_hash", "keccak")
        }

        const bbVerifyProcess = spawn("bb", verifyArgs, { stdio: "inherit" })

        bbVerifyProcess.on("error", (err) => {
            reject(new Error(`Failed to start bb process: ${err.message}`))
        })

        bbVerifyProcess.on("close", (code: number) => {
            resolve(code === 0)
        })
    })
}
