import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub"
import { poseidon2 } from "poseidon-lite"
import { Noir } from "@noir-lang/noir_js"
import { UltraPlonkBackend } from "@aztec/bb.js"
import { promises as fs } from "fs"
import { exec } from "child_process"
import { promisify } from "util"
import path from "path"

// Prime number of 251 bits.
const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n

// Prime finite field.
const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

const execAsync = promisify(exec)

const CIRCUIT_PATH = path.resolve(__dirname, "../src/main.nr")
const TARGET_PATH = path.resolve(__dirname, "../target/circuit.json")

// This function comes from packages/circuits/tests, with the added return value of merkleProofLength
function generateMerkleProof(group: Group, _index: number, maxDepth: number) {
    const { siblings: merkleProofSiblings, index } = group.generateMerkleProof(_index)
    const merkleProofLength = merkleProofSiblings.length
    // The index must be converted to a list of indices, 1 for each tree level.
    // The circuit tree depth is 20, so the number of siblings must be 20, even if
    // the tree depth is actually 3. The missing siblings can be set to 0, as they
    // won't be used to calculate the root in the circuit.
    const merkleProofIndices: number[] = []

    for (let i = 0; i < maxDepth; i += 1) {
        merkleProofIndices.push((index >> i) & 1)

        if (merkleProofSiblings[i] === undefined) {
            merkleProofSiblings[i] = BigInt(0)
        }
    }

    return { merkleProofSiblings, merkleProofIndices, merkleProofLength }
}

async function replaceDepthInCircuit(newDepth: number) {
    const circuit = await fs.readFile(CIRCUIT_PATH, "utf-8")
    const modified = circuit.replace(/pub global MAX_DEPTH: u32 = \d+;/, `pub global MAX_DEPTH: u32 = ${newDepth};`)
    await fs.writeFile(CIRCUIT_PATH, modified, "utf-8")
}

async function compileWithNargo() {
    await execAsync("nargo compile", {
        cwd: path.resolve(__dirname, "../")
    })
}

async function getCircuit() {
    const compiledJson = await fs.readFile(TARGET_PATH, "utf-8")
    return JSON.parse(compiledJson)
}

function getCircuitInput(
    leafIndex: number,
    group: Group,
    secret: bigint,
    hashedScope: number,
    hashedMessage: number,
    MAX_DEPTH: number
) {
    const { merkleProofSiblings, merkleProofIndices, merkleProofLength } = generateMerkleProof(
        group,
        leafIndex,
        MAX_DEPTH
    )

    // hashPath is the merkle proof padded with zeroes until MAX_DEPTH length
    // indexIndices indicates the input order for hashing, also padded with zeroes until MAX_DEPTH
    const hashPath = merkleProofSiblings.map((s: { toString: () => string }) => s.toString() as `0x${string}`)
    const indexIndices = merkleProofIndices.map((s: { toString: () => string }) => s.toString() as `0x${string}`)

    const secretInput = secret.toString() as `0x${string}`
    const merkleProofLengthInput = merkleProofLength.toString() as `0x${string}`
    const scopeInput = hashedScope.toString() as `0x${string}`
    const messageInput = hashedMessage.toString() as `0x${string}`

    return {
        secret_key: secretInput,
        index_bits: indexIndices,
        hash_path: hashPath,
        merkle_proof_length: merkleProofLengthInput,
        hashed_scope: scopeInput,
        hashed_message: messageInput
    }
}

async function getCompiledNoirProgram(MAX_DEPTH: number) {
    await replaceDepthInCircuit(MAX_DEPTH)
    await compileWithNargo()
    const program = await getCircuit()

    const noir = new Noir(program)
    return { noir, program }
}

async function verifyForInputs(
    noir: Noir,
    inputs: {
        secret_key: `0x${string}`
        index_bits: `0x${string}`[]
        hash_path: `0x${string}`[]
        merkle_proof_length: `0x${string}`
        hashed_scope: `0x${string}`
        hashed_message: `0x${string}`
    },
    program: any
) {
    const { witness } = await noir.execute(inputs)

    const backend = new UltraPlonkBackend(program.bytecode)
    const proof = await backend.generateProof(witness)

    const verified = await backend.verifyProof(proof)
    return { verified, proof }
}

describe("Noir Semaphore circuit", () => {
    const hashedScope = 32
    const hashedMessage = 43

    it("Should calculate the root and the nullifier correctly for prooflength 1", async () => {
        const secret = l - 1n
        const MAX_DEPTH = 10

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([2n, 3n, commitment])
        const inputs = getCircuitInput(2, group, secret, hashedScope, hashedMessage, MAX_DEPTH)

        const { noir, program } = await getCompiledNoirProgram(MAX_DEPTH)
        const { verified, proof } = await verifyForInputs(noir, inputs, program)
        const nullifier = poseidon2([hashedScope, secret])

        expect(verified).toBe(true)
        expect(BigInt(proof.publicInputs[0])).toEqual(BigInt(hashedScope))
        expect(BigInt(proof.publicInputs[1])).toEqual(BigInt(hashedMessage))
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(group.root))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)

    it("Should calculate the root and the nullifier correctly prooflength 2", async () => {
        const secret = l - 1n
        const MAX_DEPTH = 10

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([2n, 3n, 4n, 123456n, 222n, commitment])
        const leafIndex = 5
        const inputs = getCircuitInput(leafIndex, group, secret, hashedScope, hashedMessage, MAX_DEPTH)
        const { noir, program } = await getCompiledNoirProgram(MAX_DEPTH)
        const { verified, proof } = await verifyForInputs(noir, inputs, program)
        const nullifier = poseidon2([hashedScope, secret])

        expect(verified).toBe(true)
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(group.root))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)

    it("Should calculate the root and the nullifier correctly for max depth 11 and prooflength 10 for a right leaf", async () => {
        const secret = l - 1n
        const MAX_DEPTH = 11

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const leaves = Array.from({ length: 1023 }, (_, i) => BigInt(i + 1)) // 1023 dummy leaves
        leaves.push(commitment) // the leaf we're proving
        const group = new Group(leaves)
        const leafIndex = 1023 // the 124th leaf, which is a right leaf
        const inputs = getCircuitInput(leafIndex, group, secret, hashedScope, hashedMessage, MAX_DEPTH)

        const { noir, program } = await getCompiledNoirProgram(MAX_DEPTH)
        const { verified, proof } = await verifyForInputs(noir, inputs, program)
        const nullifier = poseidon2([hashedScope, secret])

        expect(verified).toBe(true)
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(group.root))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)

    it("Should calculate the root and the nullifier correctly for max depth 11 and prooflength 10 for a left leaf", async () => {
        const secret = l - 1n
        const MAX_DEPTH = 11

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const leaves = Array.from({ length: 1024 }, (_, i) => BigInt(i + 1)) // 1024 dummy leaves
        leaves.push(commitment) // the leaf we're proving
        const group = new Group(leaves)
        const leafIndex = 1024 // the 125th leaf, which is a left leaf
        const inputs = getCircuitInput(leafIndex, group, secret, hashedScope, hashedMessage, MAX_DEPTH)

        const { noir, program } = await getCompiledNoirProgram(MAX_DEPTH)
        const { verified, proof } = await verifyForInputs(noir, inputs, program)
        const nullifier = poseidon2([hashedScope, secret])

        expect(verified).toBe(true)
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(group.root))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)

    it("Should not calculate the root and the nullifier correctly if secret > l", async () => {
        const secret = l
        const MAX_DEPTH = 10

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([commitment, 2n, 3n])
        const inputs = getCircuitInput(0, group, secret, hashedScope, hashedMessage, MAX_DEPTH)

        const { noir } = await getCompiledNoirProgram(MAX_DEPTH)

        await expect(noir.execute(inputs)).rejects.toThrow(/assert/i)
    })

    it("Should not calculate the root and the nullifier correctly if secret = r - 1", async () => {
        const secret = r - 1n
        const MAX_DEPTH = 10

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([commitment, 2n, 3n])

        const inputs = getCircuitInput(0, group, secret, hashedScope, hashedMessage, MAX_DEPTH)
        const { noir } = await getCompiledNoirProgram(MAX_DEPTH)

        await expect(noir.execute(inputs)).rejects.toThrow(/assert/i)
    })

    it("Should calculate the root and the nullifier correctly using the Semaphore Identity library", async () => {
        const { commitment, secretScalar: secret } = new Identity()
        const group = new Group([commitment, 2n, 3n])
        const MAX_DEPTH = 10

        const inputs = getCircuitInput(0, group, secret, hashedScope, hashedMessage, MAX_DEPTH)
        const { noir, program } = await getCompiledNoirProgram(MAX_DEPTH)

        const { verified, proof } = await verifyForInputs(noir, inputs, program)

        const nullifier = poseidon2([hashedScope, secret])

        expect(verified).toBe(true)
        expect(BigInt(proof.publicInputs[0])).toEqual(BigInt(hashedScope))
        expect(BigInt(proof.publicInputs[1])).toEqual(BigInt(hashedMessage))
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(group.root))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)
})
