import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import {
    requireUint8Array,
    requireDefined,
    requireNumber,
    requireObject,
    requireString
} from "@zk-kit/utils/error-handlers"
import { UltraHonkBackend } from "@aztec/bb.js"
import { maybeGetCompiledNoirCircuit, Project } from "@zk-kit/artifacts"
import { CompiledCircuit } from "@noir-lang/noir_js"
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
        publicInputs: [proof.merkleTreeRoot, hash(proof.scope), hash(proof.message), proof.nullifier],
        proof: proof.proofBytes
    }
    return backend.verifyProof(proofData)
}
