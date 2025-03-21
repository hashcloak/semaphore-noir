import { requireObject, requireDefined } from "@zk-kit/utils/error-handlers"
import { ProofData, UltraHonkBackend } from "@aztec/bb.js"
import path from "path"
import fs from "fs"

// TODO change this import
const circuitPath = path.resolve(__dirname, "../../circuits/target/circuit.json")
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))

export default async function verifyNoirProof(proof: ProofData): Promise<boolean> {
    requireDefined(proof, "proof")
    requireObject(proof, "proof")

    // TODO add checks to input types

    // TODO add merkleTreeDepth check

    const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })
    return backend.verifyProof(proof)
}
