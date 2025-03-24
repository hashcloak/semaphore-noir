import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { getCurveFromName } from "ffjavascript"
import { UltraHonkBackend } from "@aztec/bb.js"
import path from "path"
import fs from "fs"
import generateNoirProof from "../src/generate-proof-noir"
import verifyNoirProof from "../src/verify-proof-noir"
import hash from "../src/hash"

const circuitPath = path.resolve(__dirname, "../../circuits/target/circuit.json")
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))

describe("Proof", () => {
    const treeDepth = 1

    const message = "Hello world"
    const scope = "Scope"

    const identity = new Identity("secret")

    let curve: any
    let backend: UltraHonkBackend

    beforeAll(async () => {
        curve = await getCurveFromName("bn128")
        backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })
    })

    afterAll(async () => {
        await curve.terminate()
    })

    describe("# generateNoirProof", () => {
        it("Should not generate a Noir Semaphore proof if the tree depth is not supported", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateNoirProof(identity, group, message, scope, 33)

            await expect(fun).rejects.toThrow("tree depth must be")
        })

        it("Should not generate Noir Semaphore proofs if the identity is not part of the group", async () => {
            const group = new Group([1n, 2n])

            const fun = () => generateNoirProof(identity, group, message, scope, treeDepth)

            await expect(fun).rejects.toThrow("does not exist")
        })

        it("Should generate a Noir Semaphore proof", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group, message, scope, treeDepth)

            // TODO extract proof.merkleTreeDepth to get correct circuit
            const proofData = {
                publicInputs: [proof.merkleTreeRoot, hash(proof.scope), hash(proof.message), proof.nullifier],
                proof: proof.proofBytes
            }
            const isValid = await backend.verifyProof(proofData)
            expect(isValid).toBe(true)
            // Manually change the message input
            proofData.publicInputs = [
                proof.merkleTreeRoot,
                hash(proof.scope),
                hash("0x0005e79a1bbec7318d980bbb060e5ecc364a2659baea61a2733b194bd353ac75"),
                proof.nullifier
            ]
            // Proof verification should fail
            const isValid2 = await backend.verifyProof(proofData)
            expect(isValid2).toBe(false)
        }, 80000)

        // TODO this doesn't work because merkle proof has different len than expected
        // it("Should generate a Noir Semaphore proof for a group with 1 member", async () => {
        //     const group = new Group([identity.commitment])

        //     const proof = await generateNoirProof(identity, group, message, scope)

        //     expect(typeof proof).toBe("object")
        //     const proofData = {
        //         publicInputs: [proof.merkleTreeRoot, proof.scope, proof.message, proof.nullifier],
        //         proof: proof.proofBytes
        //     }
        //     const isValid = await backend.verifyProof(proofData)
        //     expect(isValid).toBe(true)
        // })

        it("Should generate a Noir Semaphore proof passing a Merkle proof instead of a group", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group.generateMerkleProof(2), message, scope, treeDepth)

            expect(typeof proof).toBe("object")
            const proofData = {
                publicInputs: [proof.merkleTreeRoot, hash(proof.scope), hash(proof.message), proof.nullifier],
                proof: proof.proofBytes
            }
            const isValid = await backend.verifyProof(proofData)
            expect(isValid).toBe(true)
        })

        it("Should generate a Noir Semaphore proof without passing the tree depth", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group, message, scope)

            expect(typeof proof).toBe("object")
            const proofData = {
                publicInputs: [proof.merkleTreeRoot, hash(proof.scope), hash(proof.message), proof.nullifier],
                proof: proof.proofBytes
            }
            const isValid = await backend.verifyProof(proofData)
            expect(isValid).toBe(true)
        })

        it("Should throw an error because snarkArtifacts is not a valid path", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateNoirProof(identity, group, message, scope, undefined, "hellob#$n@ot")

            await expect(fun).rejects.toThrow("no such file or directory")
        })

        it("Should throw an error because the message value is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateNoirProof(identity, group, Number.MAX_VALUE, scope, treeDepth)

            await expect(fun).rejects.toThrow("overflow")
        })
    })

    describe("# verifyNoirProof", () => {
        it("Should not verify a Noir Semaphore proof if the tree depth is not supported", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const proof = await generateNoirProof(identity, group, message, scope, treeDepth)
            const fun = () => verifyNoirProof({ ...proof, merkleTreeDepth: 40 })
            await expect(fun).rejects.toThrow("tree depth must be")
        })
        it("Should return true if the proof is valid", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const proof = await generateNoirProof(identity, group, message, scope, treeDepth)
            const isValid = await verifyNoirProof(proof)
            expect(isValid).toBe(true)
        })
        // TODO doesn't work because merkle proof has different length
        // it("Should return false if the proof is not valid", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])
        //     const proof = await generateNoirProof(identity, group.generateMerkleProof(0), message, scope, treeDepth)
        //     const isValid = () => verifyNoirProof(proof)
        // expect(isValid).toBe(false)
        // })

        it("Should return false if the message is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const proof = await generateNoirProof(identity, group, message, scope, treeDepth)
            proof.message = "0x0005e79a1bbec7318d980bbb060e5ecc364a2659baea61a2733b194bd353ac75"

            // Proof verification should fail
            const isValid = await verifyNoirProof(proof)
            expect(isValid).toBe(false)
        }, 80000)
    })
})
