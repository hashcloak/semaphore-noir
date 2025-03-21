import type { Group, MerkleProof } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { type SnarkArtifacts } from "@zk-kit/artifacts"
import { requireDefined, requireNumber, requireObject, requireTypes } from "@zk-kit/utils/error-handlers"
import type { BigNumberish } from "ethers"
import path from "path"
import fs from "fs"
import { ProofData, UltraHonkBackend } from "@aztec/bb.js"
import { Noir } from "@noir-lang/noir_js"
import { compile, createFileManager, ProgramCompilationArtifacts } from "@noir-lang/noir_wasm"
import hash from "./hash"
import toBigInt from "./to-bigint"

// TODO how to do this in the cleanest way?
const circuitPath = path.resolve(__dirname, "../../circuits/target/circuit.json")
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))

function fromLeBits(bits: number[]): bigint {
    let result = 0n
    let v = 1n

    for (const bit of bits) {
        result += BigInt(bit) * v
        v *= 2n
    }

    return result
}

export async function getCircuit(): Promise<ProgramCompilationArtifacts> {
    // from https://github.com/noir-lang/noir/tree/master/compiler/wasm#noir-lang-wasm-javascript-package
    const fm = createFileManager(path.join(__dirname, "..", "..", "circuits/"))
    // FIXME -  cyclic dependency triggered: CyclicDependenciesError
    const noirCircuit = await compile(fm)
    return noirCircuit
}

export default async function generateNoirProof(
    identity: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    message: BigNumberish | Uint8Array | string,
    scope: BigNumberish | Uint8Array | string,
    merkleTreeDepth?: number,
    snarkArtifacts?: SnarkArtifacts
): Promise<ProofData> {
    // TODO - modify DEPTH in set_depth.nr based on merkleTreeDepth
    // this will be used by "new Noir(circuit)"
    const noirCircuit = getCircuit()
    console.log(noirCircuit)

    requireDefined(identity, "identity")
    requireDefined(groupOrMerkleProof, "groupOrMerkleProof")
    requireDefined(message, "message")
    requireDefined(scope, "scope")

    requireObject(identity, "identity")
    requireObject(groupOrMerkleProof, "groupOrMerkleProof")
    requireTypes(message, "message", ["string", "bigint", "number", "Uint8Array"])
    requireTypes(scope, "scope", ["string", "bigint", "number", "Uint8Array"])

    if (merkleTreeDepth) {
        requireNumber(merkleTreeDepth, "merkleTreeDepth")
    }

    if (snarkArtifacts) {
        requireObject(snarkArtifacts, "snarkArtifacts")
    }

    // Message and scope can be strings, numbers or buffers (i.e. Uint8Array).
    // They will be converted to bigints anyway.
    message = toBigInt(message)
    scope = toBigInt(scope)

    let merkleProof

    // The second parameter can be either a Merkle proof or a group.
    // If it is a group the Merkle proof will be calculated here.
    if ("siblings" in groupOrMerkleProof) {
        merkleProof = groupOrMerkleProof
    } else {
        const leafIndex = groupOrMerkleProof.indexOf(identity.commitment)
        merkleProof = groupOrMerkleProof.generateMerkleProof(leafIndex)
    }

    const merkleProofLength = merkleProof.siblings.length

    if (merkleTreeDepth !== undefined) {
        if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
            throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
        }
    } else {
        merkleTreeDepth = merkleProofLength !== 0 ? merkleProofLength : 1
    }

    // Prepare inputs for Noir program
    const secretKey = identity.secretScalar.toString() as `0x${string}`

    const merkleProofIndices: number[] = Array.from({ length: merkleTreeDepth }, (_, i) => (merkleProof.index >> i) & 1)
    // Convert array of bits into a single bigint
    const indexes = fromLeBits(merkleProofIndices).toString() as `0x${string}`

    const merkleProofSiblings = Array.from(merkleProof.siblings, (sibling) => sibling ?? 0n)
    // Format to valid input for circuit
    const hashPath = merkleProofSiblings.map((s) => s.toString() as `0x${string}`)

    const merkleTreeRoot = merkleProof.root.toString() as `0x${string}`
    scope = hash(scope).toString() as `0x${string}`
    message = hash(message).toString() as `0x${string}`

    // Initialize Noir with the compiled circuit
    const noir = new Noir(circuit as any)
    const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })

    // Generate witness
    const { witness } = await noir.execute({
        secretKey,
        indexes,
        hashPath,
        merkleTreeRoot,
        scope,
        message
    })

    // Generate proof
    const proofData = await backend.generateProof(witness)
    return proofData
}
