import type { Group, MerkleProof } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { requireDefined, requireObject, requireTypes } from "@zk-kit/utils/error-handlers"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import type { BigNumberish } from "ethers"
import hash from "./hash"
import toBigInt from "./to-bigint"
import { SemaphoreNoirProof } from "./types"
import { SemaphoreNoirBackend } from "./semaphore-noir-backend"

/**
 * This generates a Semaphore Noir proof; a zero-knowledge proof that an identity that
 * is part of a group has shared an anonymous message.
 *
 * The message may be any arbitrary user-defined value (e.g. a vote), or the hash of that value.
 * The scope is a value used like a topic on which users can generate a valid proof only once,
 * for example the id of an election in which voters can only vote once.
 * The hash of the identity's scope and secret scalar is called a nullifier and can be
 * used to verify whether that identity has already generated a valid proof in that scope.
 * The backend determines which UltraHonkBackend and Noir instance to use to generate the proof.
 * It is tied to the Noir circuit / merkleTreeDepth, be sure to re-initiate the backend if it is changed.
 *
 * Please keep in mind that groups with 1 member or 2 members cannot be considered anonymous.
 *
 * @param identity The Semaphore Identity
 * @param groupOrMerkleProof The Semaphore group or the Merkle proof for the identity
 * @param message The Semaphore message
 * @param scope The Semaphore scope
 * @param backend The SemaphoreNoirBackend used to generate the proof
 * @param keccak Use this option when you're using the Solidity verifier.
 * By selecting this option, the challenges in the proof will be generated with the keccak hash function instead of poseidon.
 * @returns The Semaphore Noir proof ready to be verified.
 */
export default async function generateNoirProof(
    identity: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    message: BigNumberish | Uint8Array | string,
    scope: BigNumberish | Uint8Array | string,
    backend: SemaphoreNoirBackend,
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

    if (backend.merkleTreeDepth < MIN_DEPTH || backend.merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
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

    // The index must be converted to a list of indices, 1 for each tree level.
    // The missing siblings can be set to 0, as they won't be used in the circuit.
    const merkleProofIndices = []
    const merkleProofSiblings = merkleProof.siblings

    for (let i = 0; i < backend.merkleTreeDepth; i += 1) {
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

    // Generate witness
    const { witness } = await backend.noir.execute({
        secret_key: secretKey,
        index_bits: merkleProofIndices,
        hash_path: hashPath,
        merkle_proof_length: merkleProofLength,
        hashed_scope: hashedScope,
        hashed_message: hashedMessage
    })

    // Generate proof, for verification on-chain with keccak, with poseidon otherwise
    // (This considers the hash that will be used in creating the proof, not the hash used within the circuit)
    let proofData
    if (keccak) {
        proofData = await backend.honkBackend.generateProof(witness, { keccak }, 4)
    } else {
        proofData = await backend.honkBackend.generateProof(witness, undefined, 4)
    }
    // The proofData.publicInputs consists of: [merkleTreeRoot, hashedScope, hashedMessage, nullifier]
    // Return the data as a SemaphoreNoirProof
    return {
        merkleTreeDepth: backend.merkleTreeDepth,
        merkleProofLength,
        merkleTreeRoot: merkleProof.root.toString() as `0x${string}`,
        nullifier: proofData.publicInputs[3].toString() as `0x${string}`,
        message: message.toString() as `0x${string}`,
        scope: scope.toString() as `0x${string}`,
        proofBytes: proofData.proof
    }
}
