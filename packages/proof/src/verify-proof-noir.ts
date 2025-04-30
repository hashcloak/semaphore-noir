import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import {
    requireUint8Array,
    requireDefined,
    requireNumber,
    requireObject,
    requireString
} from "@zk-kit/utils/error-handlers"
import { Project, maybeGetNoirVk } from "@zk-kit/artifacts"
import { SemaphoreNoirProof } from "./types"
import hash from "./hash"
import { SemaphoreNoirBackend } from "./semaphore-noir-backend"

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
    backend: SemaphoreNoirBackend
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

    const proofData = {
        publicInputs: [hash(proof.scope), hash(proof.message), proof.merkleTreeRoot, proof.nullifier],
        proof: proof.proofBytes
    }

    const vk = await maybeGetNoirVk(Project.SEMAPHORE_NOIR, merkleTreeDepth)

    const result = await backend.honkBackend.verifyProof(proofData, undefined, vk)

    return result
}
