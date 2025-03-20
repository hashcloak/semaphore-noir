import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { getCurveFromName } from "ffjavascript"
import { UltraHonkBackend } from "@aztec/bb.js"
import path from "path"
import fs from "fs"
import generateProof from "../src/generate-proof"
import generateNoirProof from "../src/generate-proof-noir"
import verifyProof from "../src/verify-proof"

const circuitPath = path.resolve(__dirname, "../../circuits/target/circuit.json")
const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))

describe("Proof", () => {
    const treeDepth = 10

    const message = "Hello world"
    const scope = "Scope"

    const identity = new Identity("secret")

    let curve: any

    beforeAll(async () => {
        curve = await getCurveFromName("bn128")
    })

    afterAll(async () => {
        await curve.terminate()
    })

    describe("# generateProof", () => {
        it("Should not generate a Semaphore proof if the tree depth is not supported", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateProof(identity, group, message, scope, 33)

            await expect(fun).rejects.toThrow("tree depth must be")
        })

        it("Should not generate Semaphore proofs if the identity is not part of the group", async () => {
            const group = new Group([1n, 2n])

            const fun = () => generateProof(identity, group, message, scope, treeDepth)

            await expect(fun).rejects.toThrow("does not exist")
        })

        it("Should generate a Semaphore proof", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateProof(identity, group, message, scope, treeDepth)

            expect(typeof proof).toBe("object")
            expect(BigInt(proof.merkleTreeRoot)).toBe(group.root)
        }, 80000)

        it("Should generate a Noir Semaphore proof", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group, message, scope, treeDepth)

            // TODO add verification of the proof
            const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 })
            const isValid = await backend.verifyProof(proof)
            expect(isValid).toBe(true)
            // Manually change the message input
            proof.publicInputs = [
                "0x0005e79a1bbec7318d980bbb060e5ecc364a2659baea61a2733b194bd353ac75",
                "0x26c78e51c50cebab7cdc50dfedc868f2328962c48e18c70b869886d4eebdd237"
            ]
            // Proof verification should fail
            const isValid2 = await backend.verifyProof(proof)
            expect(isValid2).toBe(false)
        }, 80000)

        it("Should generate a Semaphore proof for a group with 1 member", async () => {
            const group = new Group([identity.commitment])

            const proof = await generateProof(identity, group, message, scope)

            expect(typeof proof).toBe("object")
            expect(BigInt(proof.merkleTreeRoot)).toBe(group.root)
        })

        it("Should generate a Semaphore proof passing a Merkle proof instead of a group", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateProof(identity, group.generateMerkleProof(2), message, scope, treeDepth)

            expect(typeof proof).toBe("object")
            expect(BigInt(proof.merkleTreeRoot)).toBe(group.root)
        })

        it("Should generate a Semaphore proof without passing the tree depth", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateProof(identity, group, message, scope)

            expect(typeof proof).toBe("object")
            expect(BigInt(proof.merkleTreeRoot)).toBe(group.root)
        })

        it("Should throw an error because snarkArtifacts is not an object", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateProof(identity, group, message, scope, undefined, "hello" as any)

            await expect(fun).rejects.toThrow("is not an object")
        })

        it("Should throw an error because the message value is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateProof(identity, group, Number.MAX_VALUE, scope, treeDepth)

            await expect(fun).rejects.toThrow("overflow")
        })
    })

    describe("# verifyProof", () => {
        it("Should not verify a Semaphore proof if the tree depth is not supported", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateProof(identity, group, message, scope, treeDepth)

            const fun = () => verifyProof({ ...proof, merkleTreeDepth: 40 })

            await expect(fun).rejects.toThrow("tree depth must be")
        })

        it("Should return true if the proof is valid", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateProof(identity, group, message, scope, treeDepth)

            const response = await verifyProof(proof)

            expect(response).toBe(true)
        })

        it("Should return false if the proof is not valid", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateProof(identity, group.generateMerkleProof(0), message, scope, treeDepth)

            const response = await verifyProof(proof)

            expect(response).toBe(false)
        })
    })
})
