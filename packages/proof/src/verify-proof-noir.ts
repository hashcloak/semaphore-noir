import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import {
    requireUint8Array,
    requireDefined,
    requireNumber,
    requireObject,
    requireString
} from "@zk-kit/utils/error-handlers"
import { UltraHonkBackend } from "@aztec/bb.js"
import fs from "fs"
import { SemaphoreNoirProof } from "./types"
import hash from "./hash"
import maybeGetNoirArtifacts from "./utils"

export default async function verifyNoirProof(proof: SemaphoreNoirProof, noirArtifactsPath?: string): Promise<boolean> {
    requireDefined(proof, "proof")
    requireObject(proof, "proof")

    const { merkleTreeDepth, merkleTreeRoot, nullifier, message, scope, proofBytes } = proof

    requireNumber(merkleTreeDepth, "proof.merkleTreeDepth")
    requireString(merkleTreeRoot, "proof.merkleTreeRoot")
    requireString(nullifier, "proof.nullifier")
    requireString(message, "proof.message")
    requireString(scope, "proof.scope")
    requireUint8Array(proofBytes, "proof.proofBytes")

    // This check is for compatibility with circom.
    // The Noir circuits are parameterised by merkleProofLen and merkleProofLen <= merkleTreeDepth
    if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
    }
    if (noirArtifactsPath) {
        requireString(noirArtifactsPath, "snarkArtifacts")
    }
    // If the paths of Noir circuit json files are not defined they will be automatically downloaded.
    // The circuit is defined by the merkleProof length
    noirArtifactsPath ??= await maybeGetNoirArtifacts(proof.merkleProofLength)
    const circuit = JSON.parse(fs.readFileSync(noirArtifactsPath, "utf-8"))

    const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })
    const proofData = {
        publicInputs: [proof.merkleTreeRoot, hash(proof.scope), hash(proof.message), proof.nullifier],
        proof: proof.proofBytes
    }
    return backend.verifyProof(proofData)
}
