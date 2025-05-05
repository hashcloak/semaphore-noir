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
 * Verifies whether a Semahpore Noir proof is valid.
 * Note that the correct backend.honkBackend must be used for the proof.
 * If unsure, initialize new SemaphoreNoirBackend with proof.merkleTreeDepth.
 *
 * @param proof The Semaphore Noir proof
 * @param backend The SemaphoreNoirBackend used to generate the proof
 * @returns True if the proof is valid, false otherwise.
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
