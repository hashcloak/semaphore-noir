import type { Group, MerkleProof } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { requireDefined, requireNumber, requireObject, requireTypes } from "@zk-kit/utils/error-handlers"
import type { BigNumberish } from "ethers"
import { CompiledCircuit, Noir } from "@noir-lang/noir_js"
import { maybeGetCompiledNoirCircuit, Project } from "@zk-kit/artifacts"
import { tmpdir } from "os"
import path from "path"
import { mkdtemp, writeFile } from "fs/promises"
import { spawn } from "child_process"
import hash from "./hash"
import toBigInt from "./to-bigint"

/**
 * This generates a Semaphore Noir proof; a zero-knowledge proof that an identity that
 * is part of a group has shared an anonymous message.
 *
 * The message may be any arbitrary user-defined value (e.g. a vote), or the hash of that value.
 * The scope is a value used like a topic on which users can generate a valid proof only once,
 * for example the id of an election in which voters can only vote once.
 * The hash of the identity's scope and secret scalar is called a nullifier and can be
 * used to verify whether that identity has already generated a valid proof in that scope.
 * The merkleTreeDepth of the tree determines which zero-knowledge artifacts to use to generate the proof.
 * If it is not defined, the length of the Merkle proof is used to determine the circuit.
 * Finally, the compiled Noir circuit can be passed directly, or the correct circuit will be fetched.
 *
 * Please keep in mind that groups with 1 member or 2 members cannot be considered anonymous.
 *
 * @param identity The Semaphore Identity
 * @param groupOrMerkleProof The Semaphore group or the Merkle proof for the identity
 * @param message The Semaphore message
 * @param scope The Semaphore scope
 * @param merkleTreeDepth The depth of the tree for which the circuit was compiled
 * @param noirCompiledCircuit The precompiled Noir circuit
 * @param threads The number of threads to run the UltraHonk backend worker on.
 * For node this can be os.cpus().length, for browser it can be navigator.hardwareConcurrency
 * @param keccak Use this option when you're using the Solidity verifier.
 * By selecting this option, the challenges in the proof will be generated with the keccak hash function instead of poseidon.
 * @returns The Semaphore Noir proof ready to be verified.
 */
export default async function generateNoirProof(
    identity: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    message: BigNumberish | Uint8Array | string,
    scope: BigNumberish | Uint8Array | string,
    merkleTreeDepth?: number,
    noirCompiledCircuit?: CompiledCircuit,
    threads?: number,
    keccak?: boolean
): Promise<string> {
    // console.time("generateNoirProof-e2e");

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

    let tempDir = path.join(tmpdir(), "compiled_circuit")
    let noir: Noir
    try {
        // If the Noir circuit has not been passed, it will be automatically downloaded.
        noirCompiledCircuit ??= await maybeGetCompiledNoirCircuit(Project.SEMAPHORE_NOIR, merkleTreeDepth)

        // TODO we need a fs solution for browser (FileSystem web api?)
        // store the compiledCircuit locally for bb
        tempDir = await mkdtemp(tempDir)
        await writeFile(path.join(tempDir, "circuit.json"), JSON.stringify(noirCompiledCircuit as any))

        // Initialize Noir with the compiled circuit
        noir = new Noir(noirCompiledCircuit)
    } catch (err) {
        throw new TypeError(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
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

    let args
    if (keccak) {
        args = [
            "prove",
            "--scheme",
            "ultra_honk",
            "-b",
            path.join(tempDir, "circuit.json"),
            "-w",
            path.join(tempDir, "witness.gz"),
            "-o",
            path.normalize("./"),
            "--oracle_hash",
            "keccak"
        ]
    } else {
        args = [
            "prove",
            "--scheme",
            "ultra_honk",
            "-b",
            path.join(tempDir, "circuit.json"),
            "-w",
            path.join(tempDir, "witness.gz"),
            "-o",
            path.normalize("./")
        ]
    }

    const bbProcess = spawn("bb", args)

    bbProcess.stdout.on("data", (data) => {
        console.log(`bb_prove: ${data}`)
    })

    bbProcess.stderr.on("data", (data) => {
        console.log(`bb_prove: ${data}`)
    })

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

    // Generate proof, for verification on-chain with keccak, with poseidon otherwise
    // (This considers the hash that will be used in creating the proof, not the hash used within the circuit)
    // let proofData
    // if (keccak) {
    //     proofData = await backend.generateProof(witness, { keccak })
    // } else {
    //     proofData = await backend.generateProof(witness)
    // }
    // The proofData.publicInputs consists of: [merkleTreeRoot, hashedScope, hashedMessage, nullifier]
    // Return the data as a SemaphoreNoirProof
    // console.timeEnd("generateNoirProof-e2e");

    return path.normalize("./proof")
}
