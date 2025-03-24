import type { Group, MerkleProof } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { maybeDownload } from "@zk-kit/artifacts"
import { requireDefined, requireNumber, requireObject, requireTypes, requireString } from "@zk-kit/utils/error-handlers"
import type { BigNumberish } from "ethers"
import fs from "fs"
import { UltraHonkBackend } from "@aztec/bb.js"
import { Noir } from "@noir-lang/noir_js"
import { tmpdir } from "node:os"
import hash from "./hash"
import toBigInt from "./to-bigint"
import { SemaphoreNoirProof } from "./types"

function fromLeBits(bits: number[]): bigint {
    let result = 0n
    let v = 1n

    for (const bit of bits) {
        result += BigInt(bit) * v
        v *= 2n
    }

    return result
}

// consider merging this function to pse snark-artifacts in the future
// download precompiled circuit based on the merkleTreeDepth
async function maybeGetNoirArtifacts(merkleTreeDepth: number): Promise<string> {
    const BASE_URL = "https://github.com/hashcloak/snark-artifacts/blob/semaphore-noir/packages/semaphore-noir"
    const url = `${BASE_URL}/semaphore-noir-${merkleTreeDepth}.json?raw=true`

    const outputPath = `${tmpdir()}/semaphore-noir/${merkleTreeDepth}`
    const circuitPath = await maybeDownload(url, outputPath)

    return circuitPath
}

export default async function generateNoirProof(
    identity: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    message: BigNumberish | Uint8Array | string,
    scope: BigNumberish | Uint8Array | string,
    merkleTreeDepth?: number,
    noirArtifactsPath?: string
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

    const merkleProofIndices: number[] = Array.from({ length: merkleTreeDepth }, (_, i) => (merkleProof.index >> i) & 1)
    // Convert array of bits into a single bigint
    const indexes = fromLeBits(merkleProofIndices).toString() as `0x${string}`

    const merkleProofSiblings = Array.from(merkleProof.siblings, (sibling) => sibling ?? 0n)
    // Format to valid input for circuit
    const hashPath = merkleProofSiblings.map((s) => s.toString() as `0x${string}`)

    const merkleTreeRoot = merkleProof.root.toString() as `0x${string}`
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
        merkleTreeRoot,
        scope: hashedScope,
        message: hashedMessage
    })

    // Generate proof
    const proofData = await backend.generateProof(witness)
    return {
        merkleTreeDepth,
        merkleTreeRoot: merkleProof.root.toString() as `0x${string}`,
        nullifier: proofData.publicInputs[3].toString() as `0x${string}`,
        message: message.toString() as `0x${string}`,
        scope: scope.toString() as `0x${string}`,
        proofBytes: proofData.proof
    }
}
