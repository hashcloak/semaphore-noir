import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { poseidon2 } from "poseidon-lite"
import generateNoirProof from "../src/generate-proof-noir"
import verifyNoirProof from "../src/verify-proof-noir"
import hash from "../src/hash"
import toBigInt from "../src/to-bigint"

describe("Noir proof", () => {
    const treeDepth = 1

    const message = "Hello world"
    const scope = "Scope"

    const identity = new Identity("secret")

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

        it("Should generate a Noir Semaphore proof for merkle proof length 1", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group, message, scope, treeDepth)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        // TODO fix case for length 0 and then uncomment this
        it.skip("Should generate a Noir Semaphore proof for a group with 1 member (merkle proof of length 0)", async () => {
            const group = new Group([identity.commitment])

            const proof = await generateNoirProof(identity, group, message, scope)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        })

        it("Should generate a Noir Semaphore proof passing a Merkle proof instead of a group", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group.generateMerkleProof(2), message, scope, treeDepth)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        })

        it("Should generate a Noir Semaphore proof without passing the tree depth", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proof = await generateNoirProof(identity, group, message, scope)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        })

        it("Should throw an error because noirArtifactsPath is not a valid path", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const noirArtifactsPath = "hellob#$n@ot"
            const fun = () => generateNoirProof(identity, group, message, scope, undefined, noirArtifactsPath)

            await expect(fun).rejects.toThrow("no such file or directory")
        })

        it("Should throw an error because the message value is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateNoirProof(identity, group, Number.MAX_VALUE, scope, treeDepth)

            await expect(fun).rejects.toThrow("overflow")
        })
    })

    // TODO review these tests
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
