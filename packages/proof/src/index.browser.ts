import { packGroth16Proof, unpackGroth16Proof } from "@zk-kit/utils/proof-packing"
import generateProof from "./generate-proof"
import { generateNoirProofBrowser } from "./generate-proof-noir"
import verifyProof from "./verify-proof"
import { verifyNoirProofBrowser } from "./verify-proof-noir"

export * from "./types"

export const generateNoirProof = generateNoirProofBrowser
export const verifyNoirProof = verifyNoirProofBrowser
export { generateProof, packGroth16Proof, unpackGroth16Proof, verifyProof }
