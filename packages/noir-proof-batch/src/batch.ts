import type { SemaphoreNoirProof } from "@semaphore-protocol/proof"
import { CompiledCircuit, Noir } from "@noir-lang/noir_js"
import path from "path"
import { writeFile, mkdir } from "fs/promises"
import { UltraHonkBackend } from "@aztec/bb.js"
import { NoirBatchProof } from "./types"
import hash from "./hash"

// deflattenFields and uint8ArrayToHex come from barretenberg
const uint8ArrayToHex = (buffer: Uint8Array): string => {
    const hex: string[] = []

    buffer.forEach((i) => {
        let h = i.toString(16)
        if (h.length % 2) {
            h = `0${h}`
        }
        hex.push(h)
    })

    return `0x${hex.join("")}`
}

// https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/ts/src/proof/index.ts#L47
// But is not exported in bb.js
export function deflattenFields(flattenedFields: Uint8Array): string[] {
    const publicInputSize = 32
    const chunkedFlattenedPublicInputs: Uint8Array[] = []

    for (let i = 0; i < flattenedFields.length; i += publicInputSize) {
        const publicInput = flattenedFields.slice(i, i + publicInputSize)
        chunkedFlattenedPublicInputs.push(publicInput)
    }

    return chunkedFlattenedPublicInputs.map(uint8ArrayToHex)
}

export default async function batchSemaphoreNoirProofs(
    proofs: SemaphoreNoirProof[],
    semaphoreCircuitVk: string[], // should be 128 bytes
    // TODO make both circuits optional, so they can be retrieved
    batchLeavesCircuit: CompiledCircuit,
    batchNodesCircuit: CompiledCircuit
): Promise<NoirBatchProof> {
    const tempDir = path.normalize(path.join("./", "semaphore_artifacts"))
    let batchLeavesNoir: Noir
    // let batchNodesNoir: Noir

    // TODO just get the compiled circuit from local directly
    try {
        // store the compiled circuits locally for bb
        await mkdir(tempDir).catch((err) => {
            if (err.code !== "EEXIST") throw err
        })
        await writeFile(path.join(tempDir, `batch_2_leaves_circuit.json`), JSON.stringify(batchLeavesCircuit as any))
        await writeFile(path.join(tempDir, `batch_2_nodes_circuit.json`), JSON.stringify(batchNodesCircuit as any))

        batchLeavesNoir = new Noir(batchLeavesCircuit)
        // batchNodesNoir = new Noir(batchNodesCircuit)
    } catch (err) {
        throw new TypeError(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
    }

    const vkHash = `0x${"0".repeat(64)}`

    // To start: Assume N is a power of 2.
    // The number of initial BatchProofs in N/2
    // For each pair of SemaphoreProofs, do the following:
    const proofAsFields0 = deflattenFields(proofs[0].proofBytes)
    const publicInputs0 = [
        hash(proofs[0].scope).toString() as `0x${string}`,
        hash(proofs[0].message).toString() as `0x${string}`,
        proofs[0].merkleTreeRoot.toString() as `0x${string}`,
        proofs[0].nullifier.toString() as `0x${string}`
    ]
    const proofAsFields1 = deflattenFields(proofs[1].proofBytes)
    const publicInputs1 = [
        hash(proofs[1].scope).toString() as `0x${string}`,
        hash(proofs[1].message).toString() as `0x${string}`,
        proofs[1].merkleTreeRoot.toString() as `0x${string}`,
        proofs[1].nullifier.toString() as `0x${string}`
    ]
    const { witness: witnessPair0 } = await batchLeavesNoir.execute({
        sp: [
            {
                verification_key: semaphoreCircuitVk,
                proof: proofAsFields0,
                public_inputs: publicInputs0,
                key_hash: vkHash
            },
            {
                verification_key: semaphoreCircuitVk,
                proof: proofAsFields1,
                public_inputs: publicInputs1,
                key_hash: vkHash
            }
        ]
    })
    const nrThreads = 8 // TODO
    const backend = new UltraHonkBackend(batchLeavesCircuit.bytecode, { threads: nrThreads })

    const proofData = await backend.generateProof(witnessPair0)
    return {
        publicInputs: proofData.publicInputs,
        proofBytes: proofData.proof
    }
}
