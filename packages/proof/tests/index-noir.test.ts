import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { CompiledCircuit } from "@noir-lang/noir_js"
import generateNoirProof from "../src/generate-proof-noir-node"
import verifyNoirProof from "../src/verify-proof-noir-node"

describe("Noir proof", () => {
    const merkleTreeDepth = 10

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

            const fun = () => generateNoirProof(identity, group, message, scope, merkleTreeDepth)

            await expect(fun).rejects.toThrow("does not exist")
        })

        it("Should generate a Noir Semaphore proof for merkle proof length 1", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proofPath = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
            // const _ = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            // expect(typeof proof).toBe("object")
            // expect(proof.merkleTreeRoot).toBe(group.root.toString())
            // expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
            expect(proofPath).toContain("proof")
        }, 80000)

        // it("Should generate a Noir Semaphore proof for a group with 1 member (merkle proof of length 0)", async () => {
        //     const group = new Group([identity.commitment])
        //     const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
        //     const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        //     expect(typeof proof).toBe("object")
        //     expect(proof.merkleTreeRoot).toBe(group.root.toString())
        //     expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        // }, 80000)

        // it("Should generate a Noir Semaphore proof passing a Merkle proof instead of a group", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])

        //     const proof = await generateNoirProof(
        //         identity,
        //         group.generateMerkleProof(2),
        //         message,
        //         scope,
        //         merkleTreeDepth
        //     )
        //     const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        //     expect(typeof proof).toBe("object")
        //     expect(proof.merkleTreeRoot).toBe(group.root.toString())
        //     expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        // }, 80000)

        // it("Should generate a Noir Semaphore proof without passing the tree depth", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])

        //     const proof = await generateNoirProof(identity, group, message, scope)
        //     const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        //     expect(typeof proof).toBe("object")
        //     expect(proof.merkleTreeRoot).toBe(group.root.toString())
        //     expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        // }, 80000)

        it("Should throw an error because compiledCircuit is not a valid compiled circuit", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const dummyCircuit: CompiledCircuit = {
                bytecode: "hellob#$n@ot",
                abi: {
                    parameters: [],
                    return_type: null,
                    error_types: {}
                }
            }
            const fun = () => generateNoirProof(identity, group, message, scope, undefined, dummyCircuit)

            await expect(fun).rejects.toThrow("Failed to deserialize circuit")
        })

        it("Should throw an error because the message value is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const fun = () => generateNoirProof(identity, group, Number.MAX_VALUE, scope, merkleTreeDepth)

            await expect(fun).rejects.toThrow("overflow")
        })

        it("Should generate a Noir Semaphore proof with keccak set to true", async () => {
            const group = new Group([1n, 2n, identity.commitment])

            const proofPath = await generateNoirProof(identity, group, message, scope, merkleTreeDepth, undefined, true)
            // const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            // expect(typeof proof).toBe("object")
            // expect(proof.merkleTreeRoot).toBe(group.root.toString())
            // expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
            expect(proofPath).toContain("proof")
        }, 80000)

        // it("Should generate a Noir Semaphore proof when passing undefined merkleTreeDepth, merkleProofLength being 1", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])

        //     const proof = await generateNoirProof(identity, group, message, scope, undefined)
        //     const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        //     expect(typeof proof).toBe("object")
        //     expect(proof.merkleTreeRoot).toBe(group.root.toString())
        //     expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        // }, 80000)

        // it("Should generate a Noir Semaphore proof when passing undefined merkleTreeDepth, merkleProofLength being 0", async () => {
        //     const group = new Group([identity.commitment])
        //     const proof = await generateNoirProof(identity, group, message, scope, undefined)
        //     const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        //     expect(typeof proof).toBe("object")
        //     expect(proof.merkleTreeRoot).toBe(group.root.toString())
        //     expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        // }, 80000)
    })

    describe("# verifyNoirProof", () => {
        it("Should not verify a Noir Semaphore proof if the tree depth is not supported", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
            const fun = () => verifyNoirProof(proof, 40)
            await expect(fun).rejects.toThrow("tree depth must be")
        }, 80000)

        it("Should return true if the proof is valid", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
            const isValid = await verifyNoirProof(proof, merkleTreeDepth)
            expect(isValid).toBe(true)
        }, 80000)

        it("Should return false if the proof is not valid", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
            const isValid = await verifyNoirProof(proof, merkleTreeDepth - 2)
            expect(isValid).toBe(false)
        }, 80000)

        // it("Should return false if the message is incorrect", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])
        //     const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
        //     proof.message = "0x0005e79a1bbec7318d980bbb060e5ecc364a2659baea61a2733b194bd353ac75"

        //     const isValid = await verifyNoirProof(proof)
        //     expect(isValid).toBe(false)
        // }, 80000)

        // it("Should return false if the scope is incorrect", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])
        //     const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
        //     proof.scope = "0x0012345678"

        //     const isValid = await verifyNoirProof(proof)
        //     expect(isValid).toBe(false)
        // }, 80000)

        // it("Should return false if the merkleTreeRoot is incorrect", async () => {
        //     const group = new Group([1n, 2n, identity.commitment])
        //     const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
        //     proof.merkleTreeRoot = "0x0012345678999"

        //     const isValid = await verifyNoirProof(proof)
        //     expect(isValid).toBe(false)
        // }, 80000)

        // it("Should throw an error because compiledCircuit is not a valid compiled circuit", async () => {
        //     const dummyCircuit: CompiledCircuit = {
        //         bytecode: "hellob#$n@ot",
        //         abi: {
        //             parameters: [],
        //             return_type: null,
        //             error_types: {}
        //         }
        //     }
        //     const group = new Group([1n, 2n, identity.commitment])
        //     const proof = await generateNoirProof(identity, group, message, scope, merkleTreeDepth)
        //     const fun = () => verifyNoirProof(proof, dummyCircuit)

        //     await expect(fun).rejects.toThrow("Failed to load compiled Noir circuit")
        // })
    })
})
