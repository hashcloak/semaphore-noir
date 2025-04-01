import type { Group, MerkleProof } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { requireDefined, requireNumber, requireObject, requireTypes, requireString } from "@zk-kit/utils/error-handlers"
import type { BigNumberish } from "ethers"
import fs from "fs"
import { UltraHonkBackend } from "@aztec/bb.js"
import { Noir } from "@noir-lang/noir_js"
import hash from "./hash"
import toBigInt from "./to-bigint"
import { SemaphoreNoirProof } from "./types"
import maybeGetNoirArtifacts from "./utils"

export default async function generateNoirProof(
    identity: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    message: BigNumberish | Uint8Array | string,
    scope: BigNumberish | Uint8Array | string,
    merkleTreeDepth?: number,
    noirArtifactsPath?: string,
    keccak?: boolean
): Promise<SemaphoreNoirProof> {
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

    if (noirArtifactsPath) {
        requireString(noirArtifactsPath, "snarkArtifacts")
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

    // If the paths of Noir circuit json files are not defined they will be automatically downloaded.
    noirArtifactsPath ??= await maybeGetNoirArtifacts(merkleTreeDepth)
    const circuit = JSON.parse(fs.readFileSync(noirArtifactsPath, "utf-8"))

    // Prepare inputs for Noir program
    const secretKey = identity.secretScalar.toString() as `0x${string}`
    const merkleProofSiblings = Array.from({ length: merkleTreeDepth }, (_, i) => merkleProof.siblings[i] ?? 0n)
    // Format to valid input for circuit
    const hashPath = merkleProofSiblings.map((s) => s.toString() as `0x${string}`)
    // Index is a single number representation of the be_bits that indicate sibling index for all siblings
    const indexes = BigInt(Number.isNaN(merkleProof.index) ? 0 : merkleProof.index).toString() as `0x${string}`

    const merkleTreeRoot = merkleProof.root.toString() as `0x${string}`
    // Following the circom related implementation, pass hashes for scope and message
    const hashedScope = hash(scope).toString() as `0x${string}`
    const hashedMessage = hash(message).toString() as `0x${string}`

    // Initialize Noir with the compiled circuit
    const noir = new Noir(circuit as any)
    const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })

    // Generate witness
    const { witness } = await noir.execute({
        secretKey,
        indexes,
        hashPath,
        merkleProofLength,
        merkleTreeRoot,
        hashedScope,
        hashedMessage
    })

    // Generate proof
    let proofData
    if (keccak) {
        proofData = await backend.generateProof(witness, { keccak })
    } else {
        proofData = await backend.generateProof(witness)
    }
    return {
        merkleTreeDepth,
        merkleProofLength,
        merkleTreeRoot: merkleProof.root.toString() as `0x${string}`,
        nullifier: proofData.publicInputs[3].toString() as `0x${string}`,
        message: message.toString() as `0x${string}`,
        scope: scope.toString() as `0x${string}`,
        proofBytes: proofData.proof
    }
}
