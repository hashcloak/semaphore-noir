import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { maybeGetCompiledNoirCircuit, Project, maybeGetNoirVk } from "@zk-kit/artifacts"
import {
    requireDefined,
    requireNumber,
    requireObject,
    requireString,
    requireUint8Array
} from "@zk-kit/utils/error-handlers"
import { CompiledCircuit } from "@noir-lang/noir_js"
import { UltraHonkBackend } from "@aztec/bb.js"
import { spawn } from "child_process"
import { SemaphoreNoirProof } from "./types"
import hash from "./hash"

/**
 * Verifies whether a Semahpore Noir proof is valid. Depending on the value of
 * SemaphoreNoirProof.merkleTreeDepth, a different circuit is used.
 * (In practice that value either equals the depth of the tree of the Identities group,
 * or the length of the merkle proof used in the proof generation.)
 *
 * @param proof The Semaphore Noir proof
 * @param noirCompiledCircuit The precompiled Noir circuit
 * @param threads The number of threads to run the UltraHonk backend worker on.
 * For node this can be os.cpus().length, for browser it can be navigator.hardwareConcurrency
 * @returns
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

export async function verifyNoirProofBrowser(
    proof: SemaphoreNoirProof,
    noirCompiledCircuit?: CompiledCircuit,
    threads?: number
): Promise<boolean> {
    requireDefined(proof, "proof")
    requireObject(proof, "proof")

    const { merkleTreeDepth, merkleTreeRoot, nullifier, message, scope, proofBytes } = proof

    requireNumber(merkleTreeDepth, "proof.merkleTreeDepth")
    requireString(merkleTreeRoot, "proof.merkleTreeRoot")
    requireString(nullifier, "proof.nullifier")
    requireString(message, "proof.message")
    requireString(scope, "proof.scope")
    requireUint8Array(proofBytes, "proof.proofBytes")

    if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
    }

    // If the Noir circuit has not been passed, it will be automatically downloaded.
    // The circuit is defined by SemaphoreNoirProof.merkleTreeDepth
    let backend: UltraHonkBackend
    try {
        noirCompiledCircuit ??= await maybeGetCompiledNoirCircuit(Project.SEMAPHORE_NOIR, merkleTreeDepth)

        const nrThreads = threads ?? 1
        backend = new UltraHonkBackend(noirCompiledCircuit.bytecode, { threads: nrThreads })
    } catch (err) {
        throw new Error(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
    }

    const proofData = {
        publicInputs: [hash(proof.scope), hash(proof.message), proof.merkleTreeRoot, proof.nullifier],
        proof: proof.proofBytes
    }
    return backend.verifyProof(proofData)
}
