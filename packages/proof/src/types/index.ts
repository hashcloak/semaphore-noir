import type { NumericString } from "snarkjs"
import type { PackedGroth16Proof } from "@zk-kit/utils"

export type SemaphoreProof = {
    merkleTreeDepth: number
    merkleTreeRoot: NumericString
    message: NumericString
    nullifier: NumericString
    scope: NumericString
    points: PackedGroth16Proof
}

export type SemaphoreNoirProof = {
    merkleTreeDepth: number
    merkleTreeRoot: string
    message: string
    nullifier: string
    scope: string
    proofBytes: Uint8Array
}
