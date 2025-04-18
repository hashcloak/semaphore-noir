import { packGroth16Proof, unpackGroth16Proof } from "@zk-kit/utils/proof-packing"
import generateProof from "./generate-proof"
import generateNoirProofNode, { generateNoirProofBrowser } from "./generate-proof-noir"
import verifyProof from "./verify-proof"
import verifyNoirProofNode, { verifyNoirProofBrowser } from "./verify-proof-noir"

export * from "./types"

const isNode = typeof process !== "undefined" && !!process.versions?.node
export const generateNoirProof = isNode ? generateNoirProofNode : generateNoirProofBrowser
export const verifyNoirProof = isNode ? verifyNoirProofNode : verifyNoirProofBrowser
export { generateProof, packGroth16Proof, unpackGroth16Proof, verifyProof }
