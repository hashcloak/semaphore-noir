import type { SemaphoreNoirProof } from "@semaphore-protocol/proof"
import { Noir } from "@noir-lang/noir_js"
import {
    getCompiledBatchCircuitWithPath,
    BatchingCircuitType,
    Project,
    maybeGetBatchSemaphoreVk
} from "@zk-kit/artifacts"
import path from "path"
import os from "os"
import { mkdirSync, readFileSync } from "fs"
import { spawn } from "child_process"
import { readFile, writeFile } from "fs/promises"
import { NoirBatchProof } from "./types"
import hash from "./hash"
import { batch2LeavesCircuitVk, batch2NodesCircuitVk } from "./vks"
import { deflattenFields } from "./from-bbjs"

type InternalProof = {
    proof: NoirBatchProof
    isLayer1: boolean
}

/**
 * Wrapper to run bb CLI commands
 * @param argsArray arguments to run
 * @returns
 */
export async function runBB(argsArray: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
        const bbProcess = spawn("bb", argsArray)

        let stderr = ""

        bbProcess.stderr.on("data", (data) => {
            stderr += data.toString()
        })

        bbProcess.on("close", (code: number) => {
            if (code === 0) {
                resolve()
            } else {
                reject(new Error(`bb failed with exit code ${code}\n${stderr.trim()}`))
            }
        })
    })
}

/**
 * Recursively batches SemaphoreNoirProofs into a single proof.
 * Note: Assumes all proofs are for the same Merkle tree depth.
 * Any number of SemaphoreNoirProofs is supported. If the number is odd, 1 proof will be batched with itself in the first layer.
 * In subsequent layers any node that has no sibling is promoted to the next layer (like in LeanIMT).
 * This functionality uses recursive proofs in Noir and only works with bb cli, hence it is only available in node.
 *
 * @param proofs Semaphore Noir proofs that have been generated with `generateNoirProofForBatching`
 * @param semaphoreCircuitVk (Optional) Array of fields; verification key for the Semaphore proofs for a single merkleTreeDepth
 * @param batchLeavesCircuitPath (Optional) Path to first batching circuit (batches 2 leaves)
 * @param batchNodesCircuitPath (Optional) Path to the second batching circuit (batched 2 nodes)
 * @param keccak (Optional) Flag whether the final proof should be generated with keccak = true, which is needed for on-chain verification
 * @returns The batch proof and the path to this proof locally
 */
export default async function batchSemaphoreNoirProofs(
    proofs: SemaphoreNoirProof[],
    semaphoreCircuitVk?: string[],
    batchLeavesCircuitPath?: string,
    batchNodesCircuitPath?: string,
    keccak?: boolean
): Promise<{ proof: NoirBatchProof; path: string }> {
    if (proofs.length < 4) {
        throw new Error("At least four Semaphore proofs are required for batching.")
    }
    // Check that all proofs have the same merkleTreeDepth
    const { merkleTreeDepth } = proofs[0]
    for (const proof of proofs) {
        if (proof.merkleTreeDepth !== merkleTreeDepth) {
            throw new Error("All Semaphore proofs must have the same merkleTreeDepth.")
        }
    }
    const tempDir = path.join(os.tmpdir(), `semaphore_artifacts_${Date.now()}`)

    let batchLeavesPath: string
    let batchNodesPath: string
    let batchLeavesNoir: Noir
    let batchNodesNoir: Noir

    if (batchLeavesCircuitPath) {
        batchLeavesPath = batchLeavesCircuitPath
        const json = await readFile(batchLeavesCircuitPath, "utf-8")
        batchLeavesNoir = new Noir(JSON.parse(json))
    } else {
        const { path: leavesPath, circuit } = await getCompiledBatchCircuitWithPath(
            Project.SEMAPHORE_NOIR,
            BatchingCircuitType.Leaves
        )
        batchLeavesPath = leavesPath
        batchLeavesNoir = new Noir(circuit)
    }

    if (batchNodesCircuitPath) {
        batchNodesPath = batchNodesCircuitPath
        const json = await readFile(batchNodesCircuitPath, "utf-8")
        batchNodesNoir = new Noir(JSON.parse(json))
    } else {
        const { path: nodesPath, circuit } = await getCompiledBatchCircuitWithPath(
            Project.SEMAPHORE_NOIR,
            BatchingCircuitType.Nodes
        )
        batchNodesPath = nodesPath
        batchNodesNoir = new Noir(circuit)
    }
    // We know there are at least 3 proofs and we assume they all have the same tree depth
    let semaphoreCircuitVkFinal: string[]
    if (!semaphoreCircuitVk) {
        semaphoreCircuitVkFinal = await maybeGetBatchSemaphoreVk(Project.SEMAPHORE_NOIR, merkleTreeDepth)
    } else {
        semaphoreCircuitVkFinal = semaphoreCircuitVk
    }

    const vkHash = `0x${"0".repeat(64)}`

    // STEP 1: Generate the first layer of proofs, combining Semaphore proofs per pair
    // If there is an odd number of proofs, the final one will be batched with itself
    const leafLayerProofs: InternalProof[] = []
    const recursion = path.join(tempDir, "recursion")
    mkdirSync(recursion, { recursive: true })

    const leafProofs = [...proofs]

    // If the number of Semaphore proofs is odd, self-pair the last one
    if (leafProofs.length % 2 === 1) {
        const lastProof = leafProofs[leafProofs.length - 1]
        leafProofs.push(lastProof)
    }

    for (let i = 0; i < leafProofs.length; i += 2) {
        const proof0 = leafProofs[i]
        const proof1 = leafProofs[i + 1]

        const proofAsFields0 = deflattenFields(proof0.proofBytes)
        const publicInputs0 = [
            hash(proof0.scope).toString() as `0x${string}`,
            hash(proof0.message).toString() as `0x${string}`,
            proof0.merkleTreeRoot.toString() as `0x${string}`,
            proof0.nullifier.toString() as `0x${string}`
        ]

        const proofAsFields1 = deflattenFields(proof1.proofBytes)
        const publicInputs1 = [
            hash(proof1.scope).toString() as `0x${string}`,
            hash(proof1.message).toString() as `0x${string}`,
            proof1.merkleTreeRoot.toString() as `0x${string}`,
            proof1.nullifier.toString() as `0x${string}`
        ]

        const { witness } = await batchLeavesNoir.execute({
            sp: [
                {
                    verification_key: semaphoreCircuitVkFinal,
                    proof: proofAsFields0,
                    public_inputs: publicInputs0,
                    key_hash: vkHash
                },
                {
                    verification_key: semaphoreCircuitVkFinal,
                    proof: proofAsFields1,
                    public_inputs: publicInputs1,
                    key_hash: vkHash
                }
            ]
        })
        await writeFile(`${recursion}/witness_${i}.gz`, witness)
        mkdirSync(`${recursion}/leaves_${i}`, { recursive: true })

        await runBB([
            "prove",
            "--output_format",
            "bytes_and_fields",
            "-b",
            batchLeavesPath,
            "-w",
            `${recursion}/witness_${i}.gz`,
            "-o",
            `${recursion}/leaves_${i}`,
            "--recursive"
        ])
        const proofFields = JSON.parse(readFileSync(`${recursion}/leaves_${i}/proof_fields.json`, "utf-8"))

        leafLayerProofs.push({
            proof: {
                publicInputs: [],
                proofBytes: proofFields
            },
            isLayer1: true
        })
    }

    // STEP 2: Now aggregate the proofs recursively per 2. If there is an odd number of nodes,
    // the last node is promoted to the next level.
    let currentLayerProofs: InternalProof[] = leafLayerProofs

    // Keep batching node layers until only 1 proof remains
    let layer = 1
    while (currentLayerProofs.length > 1) {
        const nextLayerProofs: InternalProof[] = []
        for (let i = 0; i < currentLayerProofs.length; i += 2) {
            const proof0 = currentLayerProofs[i]
            const proof1 = currentLayerProofs[i + 1]
            // If proof1 is undefined this layer had an odd number of proofs
            // and we promote the odd one to the next level
            if (!proof1) {
                nextLayerProofs.push(proof0)
            } else {
                const { witness } = await batchNodesNoir.execute({
                    bp: [
                        {
                            verification_key: proof0.isLayer1 ? batch2LeavesCircuitVk : batch2NodesCircuitVk,
                            proof: proof0.proof.proofBytes,
                            key_hash: vkHash
                        },
                        {
                            verification_key: proof1.isLayer1 ? batch2LeavesCircuitVk : batch2NodesCircuitVk,
                            proof: proof1.proof.proofBytes,
                            key_hash: vkHash
                        }
                    ]
                })
                await writeFile(`${recursion}/witness_nodes_${layer}_${i}.gz`, witness)
                mkdirSync(`${recursion}/node_${layer}_${i}`, { recursive: true })

                const args = [
                    "prove",
                    "--output_format",
                    "bytes_and_fields",
                    "-b",
                    batchNodesPath,
                    "-w",
                    `${recursion}/witness_nodes_${layer}_${i}.gz`,
                    "-o",
                    `${recursion}/node_${layer}_${i}`,
                    "--recursive"
                ]
                // When creating the last proof, check if we need to generate it with keccak flag
                if (currentLayerProofs.length === 2 && keccak) {
                    args.push("--oracle_hash")
                    args.push("keccak")
                }
                await runBB(args)
                const proofFields = JSON.parse(
                    readFileSync(`${recursion}/node_${layer}_${i}/proof_fields.json`, "utf-8")
                )

                nextLayerProofs.push({
                    proof: {
                        publicInputs: [],
                        proofBytes: proofFields
                    },
                    isLayer1: false
                })
            }
        }

        // Prepare next loop
        currentLayerProofs = nextLayerProofs
        layer += 1
    }

    // Return the "root" batch proof
    const finalProofPath = `${recursion}/node_${layer - 1}_0/proof`
    const rootBatchProof = currentLayerProofs[0].proof

    return {
        proof: rootBatchProof,
        path: finalProofPath
    }
}
