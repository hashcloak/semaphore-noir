import { packGroth16Proof, unpackGroth16Proof } from "@zk-kit/utils/proof-packing"
import generateProof from "./generate-proof"
import generateNoirProof from "./generate-proof-noir"
import verifyProof from "./verify-proof"
import verifyNoirProof from "./verify-proof-noir"
import { SemaphoreNoirBackend, initSemaphoreNoirBackend, getMerkleTreeDepth } from "./semaphore-noir-backend"

export * from "./types"
export {
    generateNoirProof,
    generateProof,
    packGroth16Proof,
    unpackGroth16Proof,
    verifyProof,
    verifyNoirProof,
    SemaphoreNoirBackend,
    initSemaphoreNoirBackend,
    getMerkleTreeDepth
}
