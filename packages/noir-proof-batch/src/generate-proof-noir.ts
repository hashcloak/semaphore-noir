import type { Group, MerkleProof } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { requireDefined, requireNumber, requireObject, requireTypes } from "@zk-kit/utils/error-handlers"
import type { BigNumberish } from "ethers"
import { CompiledCircuit, Noir } from "@noir-lang/noir_js"
import { getCompiledNoirCircuitWithPath, Project } from "@zk-kit/artifacts"
import { SemaphoreNoirProof } from "@semaphore-protocol/proof"
import path from "path"
import fs from "fs"
import os from "os"
import { writeFile, mkdir } from "fs/promises"
import { spawn } from "child_process"
import hash from "./hash"
import toBigInt from "./to-bigint"

// Functionality from https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/ts/src/proof/index.ts#L59
// That is not exported in their module
function hexToUint8Array(hex: string): Uint8Array {
    const sanitisedHex = BigInt(hex).toString(16).padStart(64, "0")

    const len = sanitisedHex.length / 2
    const u8 = new Uint8Array(len)

    let i = 0
    let j = 0
    while (i < len) {
        u8[i] = parseInt(sanitisedHex.slice(j, j + 2), 16)
        i += 1
        j += 2
    }

    return u8
}

function flattenUint8Arrays(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((acc, val) => acc + val.length, 0)
    const result = new Uint8Array(totalLength)

    let offset = 0
    for (const arr of arrays) {
        result.set(arr, offset)
        offset += arr.length
    }

    return result
}

export function flattenFieldsAsArray(fields: string[]): Uint8Array {
    const flattenedPublicInputs = fields.map(hexToUint8Array)
    return flattenUint8Arrays(flattenedPublicInputs)
}

/**
 * This generates a Semaphore Noir proof suitable for batching.
 * Note that *only* Semaphore Noir proofs generated with this function can be batched.
 * The "normal" generation function will not suffice.
 *
 * The functionality is the same as `generateNoirProof` in `packages/proof`.
 * The difference is that this proof is generated with bb CLI, and with the
 * necessary flags for recursion (which is used for batching).
 *
 * @param identity The Semaphore Identity
 * @param groupOrMerkleProof The Semaphore group or the Merkle proof for the identity
 * @param message The Semaphore message
 * @param scope The Semaphore scope
 * @param merkleTreeDepth The depth of the tree for which the circuit was compiled
 * @param circuitPath Optional path to the precompiled circuit
 *
 * Note: This proof shouldn't be generated with the `keccak` flag, since it will be batched with other proofs.
 * @returns The Semaphore Noir proof ready to be verified off-chain, or batched together with other SemaphoreProofs
 */
export default async function generateNoirProofForBatching(
    identity: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    message: BigNumberish | Uint8Array | string,
    scope: BigNumberish | Uint8Array | string,
    merkleTreeDepth?: number,
    circuitPath?: string
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

    // If the merkleTreeDepth is not passed, the length of the merkle proof is used.
    // Note that this value can be smaller than the actual depth of the tree
    const merkleProofLength = merkleProof.siblings.length
    if (merkleTreeDepth !== undefined) {
        if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
            throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
        }
    } else {
        merkleTreeDepth = merkleProofLength !== 0 ? merkleProofLength : 1
    }

    // The index must be converted to a list of indices, 1 for each tree level.
    // The missing siblings can be set to 0, as they won't be used in the circuit.
    const merkleProofIndices = []
    const merkleProofSiblings = merkleProof.siblings

    for (let i = 0; i < merkleTreeDepth; i += 1) {
        merkleProofIndices.push((merkleProof.index >> i) & 1)

        if (merkleProofSiblings[i] === undefined) {
            merkleProofSiblings[i] = 0n
        }
    }

    // Prepare inputs for Noir program
    const secretKey = identity.secretScalar.toString() as `0x${string}`
    // Format to valid input for circuit
    const hashPath = merkleProofSiblings.map((s) => s.toString() as `0x${string}`)

    // Following the circom related implementation, pass hashes for scope and message
    const hashedScope = hash(scope).toString() as `0x${string}`
    const hashedMessage = hash(message).toString() as `0x${string}`

    const tempDir = path.join(os.tmpdir(), "semaphore_artifacts")
    const timestamp = Date.now()
    const proofOutputDir = path.join(tempDir, `${timestamp}`)
    await mkdir(proofOutputDir, { recursive: true })

    let compiledCircuit: CompiledCircuit
    let noir: Noir

    try {
        if (!circuitPath) {
            const result = await getCompiledNoirCircuitWithPath(Project.SEMAPHORE_NOIR, merkleTreeDepth)
            circuitPath = result.path
            compiledCircuit = result.circuit
        } else {
            const raw = await fs.promises.readFile(circuitPath, "utf-8")
            compiledCircuit = JSON.parse(raw) as CompiledCircuit
        }
        noir = new Noir(compiledCircuit)
    } catch (err) {
        throw new TypeError(`Failed to instantiate Noir: ${(err as Error).message}`)
    }

    // Generate witness
    const { witness } = await noir.execute({
        secret_key: secretKey,
        index_bits: merkleProofIndices,
        hash_path: hashPath,
        merkle_proof_length: merkleProofLength,
        hashed_scope: hashedScope,
        hashed_message: hashedMessage
    })
    // store witness
    await writeFile(path.join(tempDir, "witness.gz"), witness)

    // Generate the proof with bb cli
    const args = [
        "prove",
        "--scheme",
        "ultra_honk",
        "-b",
        circuitPath,
        "-w",
        path.join(tempDir, "witness.gz"),
        "-o",
        `${tempDir}/${timestamp}`,
        "--output_format",
        "bytes_and_fields",
        "--honk_recursion",
        "1",
        "--recursive",
        "--init_kzg_accumulator"
    ]

    const bbProcess = spawn("bb", args)
    bbProcess.on("error", (err) => {
        throw new Error(`Failed to start process: ${err.message}`)
    })

    await new Promise((resolve, reject) => {
        bbProcess.on("close", (code: number) => {
            if (code === 0) {
                resolve(0)
            } else {
                reject(new Error(`Process exited with code ${code}`))
            }
        })
    })

    // Read out the proof data and return
    // In the Semaphore circuit we have 4 public inputs
    const publicInputsCount = 4
    const proofFields = JSON.parse(fs.readFileSync(`${tempDir}/${timestamp}/proof_fields.json`, "utf-8"))
    const publicInputs = proofFields.slice(0, publicInputsCount)
    const proofAsFields = [...proofFields.slice(publicInputsCount)]

    return {
        merkleTreeDepth,
        merkleProofLength,
        merkleTreeRoot: merkleProof.root.toString() as `0x${string}`,
        nullifier: publicInputs[3].toString() as `0x${string}`,
        message: message.toString() as `0x${string}`,
        scope: scope.toString() as `0x${string}`,
        proofBytes: flattenFieldsAsArray(proofAsFields)
    }
}
