import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { poseidon2 } from "poseidon-lite"
import { CompiledCircuit } from "@noir-lang/noir_js"
import { initSemaphoreNoirBackend, getMerkleTreeDepth } from "@semaphore-protocol/proof"
import generateNoirProof from "../src/generate-proof-noir"
import verifyNoirProof from "../src/verify-proof-noir"
import hash from "../src/hash"
import toBigInt from "../src/to-bigint"

describe("Noir proof", () => {
    const merkleTreeDepth = 10

    const message = "Hello world"
    const scope = "Scope"

    const identity = new Identity("secret")

    describe("# generateNoirProof", () => {
        it("Should not generate Noir Semaphore proofs if the identity is not part of the group", async () => {
            const group = new Group([1n, 2n])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const fun = () => generateNoirProof(identity, group, message, scope, backend)

            await expect(fun).rejects.toThrow("does not exist")
        })

        it("Should generate a Noir Semaphore proof for merkle proof length 1", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        it("Should generate a Noir Semaphore proof for a group with 1 member (merkle proof of length 0)", async () => {
            const group = new Group([identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        it("Should generate a Noir Semaphore proof passing a Merkle proof instead of a group", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group.generateMerkleProof(2), message, scope, backend)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        it("Should generate a Noir Semaphore proof without passing the tree depth", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        it("Should throw an error because compiledCircuit is not a valid compiled circuit", async () => {
            const dummyCircuit: CompiledCircuit = {
                bytecode: "hellob#$n@ot",
                abi: {
                    parameters: [],
                    return_type: null,
                    error_types: {}
                },
                debug_symbols: "test",
                file_map: {}
            }

            const fun = () => initSemaphoreNoirBackend(2, dummyCircuit)

            await expect(fun).rejects.toThrow("Failed to load compiled Noir circuit")
        })

        it("Should throw an error because the message value is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const fun = () => generateNoirProof(identity, group, Number.MAX_VALUE, scope, backend)

            await expect(fun).rejects.toThrow("overflow")
        })

        it("Should throw an error if the tree depth is not supported", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            backend.merkleTreeDepth = 100
            const fun = () => generateNoirProof(identity, group, Number.MAX_VALUE, scope, backend)

            await expect(fun).rejects.toThrow("The tree depth must be a number between")
        })

        it("Should generate a Noir Semaphore proof with keccak set to true", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend, true)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        it("Should generate a Noir Semaphore proof with MerkleTreeDepth from getMerkleTreeDepth() , merkleProofLength being 1", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const newMerkleTreeDepth = getMerkleTreeDepth(identity, group)
            const backend = await initSemaphoreNoirBackend(newMerkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)

        it("Should generate a Noir Semaphore proof with MerkleTreeDepth from getMerkleTreeDepth(), merkleProofLength being 0", async () => {
            const group = new Group([identity.commitment])
            const leafIndex = group.indexOf(identity.commitment)
            const merkleProof = group.generateMerkleProof(leafIndex)
            const newMerkleTreeDepth = getMerkleTreeDepth(identity, merkleProof)
            const backend = await initSemaphoreNoirBackend(newMerkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            const nullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

            expect(typeof proof).toBe("object")
            expect(proof.merkleTreeRoot).toBe(group.root.toString())
            expect(BigInt(proof.nullifier)).toBe(BigInt(nullifier))
        }, 80000)
    })

    describe("# verifyNoirProof", () => {
        it("Should return true if the proof is valid", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            const isValid = await verifyNoirProof(proof, backend)
            expect(isValid).toBe(true)
        }, 80000)

        it("Should return false if the message is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            proof.message = "0x0005e79a1bbec7318d980bbb060e5ecc364a2659baea61a2733b194bd353ac75"

            const isValid = await verifyNoirProof(proof, backend)
            expect(isValid).toBe(false)
        }, 80000)

        it("Should return false if the scope is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            proof.scope = "0x0012345678"

            const isValid = await verifyNoirProof(proof, backend)
            expect(isValid).toBe(false)
        }, 80000)

        it("Should return false if the merkleTreeRoot is incorrect", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            proof.merkleTreeRoot = "0x0012345678999"

            const isValid = await verifyNoirProof(proof, backend)
            expect(isValid).toBe(false)
        }, 80000)

        it("Should throw an error because compiledCircuit is not a valid compiled circuit", async () => {
            const dummyCircuit: CompiledCircuit = {
                bytecode: "hellob#$n@ot",
                abi: {
                    parameters: [],
                    return_type: null,
                    error_types: {}
                },
                debug_symbols: "test",
                file_map: {}
            }
            const fun = () => initSemaphoreNoirBackend(2, dummyCircuit)

            await expect(fun).rejects.toThrow("Failed to load compiled Noir circuit")
        })

        it("Should throw an error if merkleTreeDepth exceeds the limit", async () => {
            const group = new Group([1n, 2n, identity.commitment])
            const backend = await initSemaphoreNoirBackend(merkleTreeDepth)
            const proof = await generateNoirProof(identity, group, message, scope, backend)
            proof.merkleTreeDepth = 1000

            await expect(verifyNoirProof(proof, backend)).rejects.toThrow("The tree depth must be a number between")
        })
    })
    describe("# SemaphoreNoirBackend", () => {
        it("Should not generate backend if the tree depth is not supported", async () => {
            const fun = () => initSemaphoreNoirBackend(55)
            await expect(fun).rejects.toThrow("tree depth must be")
        })
    })
})
