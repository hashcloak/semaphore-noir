import { runBB } from "./batch"

export default async function verifyNoirProof(vkPath: string, proofPath: string): Promise<boolean> {
    await runBB(["verify", "-k", vkPath, "-p", proofPath])
    return true
}
