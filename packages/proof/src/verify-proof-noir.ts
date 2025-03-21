import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import {
    requireUint8Array,
    requireDefined,
    requireNumber,
    requireObject,
    requireString
} from "@zk-kit/utils/error-handlers"
import { UltraHonkBackend } from "@aztec/bb.js"
import path from "path"
import fs from "fs"
import { SemaphoreNoirProof } from "./types"
import hash from "./hash"

// TODO change this import
const circuitPath = path.resolve(__dirname, "../../circuits/target/circuit.json")
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))

export default async function verifyNoirProof(proof: SemaphoreNoirProof): Promise<boolean> {
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

    const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })
    const proofData = {
        publicInputs: [proof.merkleTreeRoot, hash(proof.scope), hash(proof.message), proof.nullifier],
        proof: proof.proofBytes
    }
    return backend.verifyProof(proofData)
}
