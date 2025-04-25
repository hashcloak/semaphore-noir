import { readFile } from "fs/promises"
import path from "path"
import type { SemaphoreNoirProof } from "@semaphore-protocol/proof"
import { batchSemaphoreNoirProofs } from "@semaphore-protocol/noir-proof-batch"

const batchLeavesCircuitPath = path.join(__dirname, "../circuits/batch_2_leaves/target/batch_2_leaves.json")
const batchNodesCircuitPath = path.join(__dirname, "../circuits/batch_2_nodes/target/batch_2_nodes.json")

describe("batchSemaphoreNoirProofs", () => {
    it("should batch two dummy Semaphore proofs", async () => {
        // Load compiled circuits, local for now.
        const batchLeavesCircuit = JSON.parse(await readFile(batchLeavesCircuitPath, "utf8"))
        const batchNodesCircuit = JSON.parse(await readFile(batchNodesCircuitPath, "utf8"))

        // TODO add actual proofs
        const dummyProofs: SemaphoreNoirProof[] = [
            {
                merkleTreeDepth: 10,
                merkleProofLength: 1,
                merkleTreeRoot: "0x01",
                message: "0x02",
                nullifier: "0x03",
                scope: "0x04",
                proofBytes: new Uint8Array(32 * 456)
            },
            {
                merkleTreeDepth: 10,
                merkleProofLength: 1,
                merkleTreeRoot: "0x05",
                message: "0x06",
                nullifier: "0x07",
                scope: "0x08",
                proofBytes: new Uint8Array(32 * 456)
            }
        ]

        // Verification key input
        const dummyVk = Array(128).fill("0x00")

        const result = await batchSemaphoreNoirProofs(dummyProofs, dummyVk, batchLeavesCircuit, batchNodesCircuit)

        expect(result).toBeDefined()
    })
})
