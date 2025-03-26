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
import { generateMerkleProof } from "./common"

// Prime number of 251 bits.
const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n

// Prime finite field.
const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

const execAsync = promisify(exec)

const CIRCUIT_PATH = path.resolve(__dirname, "../src/main.nr")
const TARGET_PATH = path.resolve(__dirname, "../target/circuit.json")

async function replaceDepthInCircuit(newDepth: number) {
    const circuit = await fs.readFile(CIRCUIT_PATH, "utf-8")
    const modified = circuit.replace(/pub global DEPTH: u32 = \d+;/, `pub global DEPTH: u32 = ${newDepth};`)
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

// TODO add to utils
function fromLeBits(bits: number[]): bigint {
    let result = 0n
    let v = 1n

    for (const bit of bits) {
        result += BigInt(bit) * v
        v *= 2n
    }

    return result
}
function getCircuitInput(group: Group, testDepth: number, secret: bigint, scope: number, message: number) {
    const { merkleProofSiblings, merkleProofIndices } = generateMerkleProof(group, 0, testDepth)
    const secretInput = secret.toString() as `0x${string}`
    const hashPath = merkleProofSiblings.map((s: { toString: () => string }) => s.toString() as `0x${string}`)
    const indexes = fromLeBits(merkleProofIndices).toString() as `0x${string}`
    const merkleTreeRoot = group.root.toString() as `0x${string}`
    const scopeInput = scope.toString() as `0x${string}`
    const messageInput = message.toString() as `0x${string}`

    return {
        secretKey: secretInput,
        indexes,
        hashPath,
        merkleTreeRoot,
        scope: scopeInput,
        message: messageInput
    }
}

describe("Noir Semaphore circuit", () => {
    let testDepth = 10

    const scope = 32
    const message = 43

    it("Should calculate the root and the nullifier correctly", async () => {
        const secret = l - 1n

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([commitment, 2n, 3n])
        testDepth = group.depth

        await replaceDepthInCircuit(testDepth)
        await compileWithNargo()
        const program = await getCircuit()

        const inputs = getCircuitInput(group, testDepth, secret, scope, message)

        const noir = new Noir(program)
        const { witness } = await noir.execute(inputs)

        const backend = new UltraPlonkBackend(program.bytecode)
        const proof = await backend.generateProof(witness)

        const verified = await backend.verifyProof(proof)
        expect(verified).toBe(true)
    }, 80000)

    it("Should not calculate the root and the nullifier correctly if secret > l", async () => {
        const secret = l

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([commitment, 2n, 3n])
        testDepth = group.depth

        await replaceDepthInCircuit(testDepth)
        await compileWithNargo()
        const program = await getCircuit()

        const inputs = getCircuitInput(group, testDepth, secret, scope, message)
        const noir = new Noir(program)

        await expect(noir.execute(inputs)).rejects.toThrow(/assert/i)
    })

    it("Should not calculate the root and the nullifier correctly if secret = r - 1", async () => {
        const secret = r - 1n

        const commitment = poseidon2(mulPointEscalar(Base8, secret))
        const group = new Group([commitment, 2n, 3n])
        testDepth = group.depth

        await replaceDepthInCircuit(testDepth)
        await compileWithNargo()
        const program = await getCircuit()

        const inputs = getCircuitInput(group, testDepth, secret, scope, message)
        const noir = new Noir(program)

        await expect(noir.execute(inputs)).rejects.toThrow(/assert/i)
    })

    it("Should calculate the root and the nullifier correctly using the Semaphore Identity library", async () => {
        const { commitment, secretScalar: secret } = new Identity()

        const group = new Group([commitment, 2n, 3n])
        testDepth = group.depth

        await replaceDepthInCircuit(testDepth)
        await compileWithNargo()
        const program = await getCircuit()

        const inputs = getCircuitInput(group, testDepth, secret, scope, message)

        const noir = new Noir(program)
        const { witness } = await noir.execute(inputs)

        const backend = new UltraPlonkBackend(program.bytecode)
        const proof = await backend.generateProof(witness)

        const verified = await backend.verifyProof(proof)

        const nullifier = poseidon2([scope, secret])

        expect(verified).toBe(true)
        expect(BigInt(proof.publicInputs[0])).toEqual(group.root)
        expect(BigInt(proof.publicInputs[1])).toEqual(BigInt(scope))
        expect(BigInt(proof.publicInputs[2])).toEqual(BigInt(message))
        expect(BigInt(proof.publicInputs[3])).toEqual(nullifier)
    }, 80000)

    // TODO add tests for various depths
})
