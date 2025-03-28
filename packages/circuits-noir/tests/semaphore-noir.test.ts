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
    const { siblings: merkleProofSiblings, index } = group.generateMerkleProof(leafIndex)
    // The merkleProofLength is the actual merkle proof length without padding of zeroes
    const merkleProofLength = merkleProofSiblings.length.toString() as `0x${string}`
    // HashPath is the merkle proof padded with zeroes until MAX_DEPTH length
    const hashPath = merkleProofSiblings.map((s: { toString: () => string }) => s.toString() as `0x${string}`)
    while (hashPath.length < MAX_DEPTH) {
        hashPath.push("0x00")
    }

    const secretInput = secret.toString() as `0x${string}`
    const indexes = index.toString() as `0x${string}`
    const merkleTreeRoot = group.root.toString() as `0x${string}`
    const scopeInput = hashedScope.toString() as `0x${string}`
    const messageInput = hashedMessage.toString() as `0x${string}`

    return {
        secretKey: secretInput,
        indexes,
        hashPath,
        merkleProofLength,
        merkleTreeRoot,
        hashedScope: scopeInput,
        hashedMessage: messageInput
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
        secretKey: `0x${string}`
        indexes: `0x${string}`
        hashPath: `0x${string}`[]
        merkleProofLength: `0x${string}`
        merkleTreeRoot: `0x${string}`
        hashedScope: `0x${string}`
        hashedMessage: `0x${string}`
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
        expect(BigInt(proof.publicInputs[0])).toEqual(group.root)
        expect(BigInt(proof.publicInputs[1])).toEqual(BigInt(hashedScope))
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(hashedMessage))
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
        expect(BigInt(proof.publicInputs[0])).toEqual(group.root)
        expect(BigInt(proof.publicInputs[1])).toEqual(BigInt(hashedScope))
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(hashedMessage))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)
})
