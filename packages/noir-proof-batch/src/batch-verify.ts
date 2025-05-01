import { spawn } from "child_process"

export default async function verifyNoirProof(vkPath: string, proofPath: string, keccak?: boolean): Promise<boolean> {
    return new Promise((resolve, reject) => {
        const verifyArgs = ["verify", "--scheme", "ultra_honk", "-k", vkPath, "-p", proofPath]
        if (keccak) {
            // Note that also the verification key must have been generated with keccak flag
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
