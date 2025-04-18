import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { maybeGetCompiledNoirCircuit, Project } from "@zk-kit/artifacts"
import {
    requireDefined,
    requireNumber,
    requireObject,
    requireString,
    requireUint8Array
} from "@zk-kit/utils/error-handlers"
import { CompiledCircuit } from "@noir-lang/noir_js"
import { UltraHonkBackend } from "@aztec/bb.js"
import path from "path"
import { mkdir, writeFile } from "fs/promises"
import { spawn } from "child_process"
import { SemaphoreNoirProof } from "./types"
import hash from "./hash"

/**
 * Verifies whether a Semahpore Noir proof is valid. Depending on the value of
 * SemaphoreNoirProof.merkleTreeDepth, a different circuit is used.
 * (In practice that value either equals the depth of the tree of the Identities group,
 * or the length of the merkle proof used in the proof generation.)
 *
 * @param proof The Semaphore Noir proof
 * @param noirCompiledCircuit The precompiled Noir circuit
 * @param threads The number of threads to run the UltraHonk backend worker on.
 * For node this can be os.cpus().length, for browser it can be navigator.hardwareConcurrency
 * @returns
 */
export default async function verifyNoirProof(
    proofPath: string,
    merkleTreeDepth: number,
    noirCompiledCircuit?: CompiledCircuit
): Promise<boolean> {
    // console.time("verifyNoirProof-e2e");
    if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
    }

    // console.time("verifyNoirProof-maybeGetCompiledNoirCircuit");
    // TODO change this to os.tmpdir()
    // If the Noir circuit has not been passed, it will be automatically downloaded.
    // The circuit is defined by SemaphoreNoirProof.merkleTreeDepth
    const tempDir = path.normalize(path.join("./", "semaphore_artifacts"))
    try {
        // TODO consider making maybeGetCompiledNoirCircuit return the path instead of the object
        noirCompiledCircuit ??= await maybeGetCompiledNoirCircuit(Project.SEMAPHORE_NOIR, merkleTreeDepth)

        // TODO we need a fs solution for browser (FileSystem web api?)
        // store the compiledCircuit locally for bb
        await mkdir(tempDir).catch((err) => {
            if (err.code !== "EEXIST") throw err
        })
        await writeFile(
            path.join(tempDir, `circuit_${merkleTreeDepth}.json`),
            JSON.stringify(noirCompiledCircuit as any)
        )
    } catch (err) {
        throw new Error(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
    }
    // console.timeEnd("verifyNoirProof-maybeGetCompiledNoirCircuit");

    // console.time("verifyNoirProof-write_vk");
    // start bb write_vk
    const writeVkArgs = [
        "write_vk",
        "--scheme",
        "ultra_honk",
        "-b",
        path.join(tempDir, `circuit_${merkleTreeDepth}.json`),
        "-o",
        tempDir
    ]
    const bbVkProcess = spawn("bb", writeVkArgs)
    bbVkProcess.stdout.on("data", (data) => {
        console.log(`bb_vk: ${data}`)
    })
    bbVkProcess.stderr.on("data", (data) => {
        console.log(`bb_vk: ${data}`)
    })
    bbVkProcess.on("error", (err) => {
        throw new Error(`Failed to start process: ${err.message}`)
    })
    await new Promise((resolve) => {
        bbVkProcess.on("close", (code) => {
            if (code === 0) {
                console.log("proof generation succeed")
                resolve(true)
            } else {
                throw new Error(`Failed to generate vk: ${code}`)
            }
        })
    })
    // console.timeEnd("verifyNoirProof-write_vk");

    // start bb_verify
    // console.time("verifyNoirProof-verify");
    let result = false
    const verifyArgs = ["verify", "--scheme", "ultra_honk", "-k", path.join(tempDir, "vk"), "-p", proofPath]
    const bbVerifyProcess = spawn("bb", verifyArgs)
    bbVerifyProcess.stdout.on("data", (data) => {
        console.log(`bb_verify ${data}`)
    })
    bbVerifyProcess.stderr.on("data", (data) => {
        console.log(`bb_verify: ${data}`)
    })
    bbVerifyProcess.on("error", (err) => {
        throw new Error(`Failed to start process: ${err.message}`)
    })
    result = await new Promise((resolve) => {
        bbVerifyProcess.on("close", (code: number) => {
            if (code === 0) {
                resolve(true)
            } else {
                resolve(false)
            }
        })
    })
    // console.timeEnd("verifyNoirProof-verify");

    // console.timeEnd("verifyNoirProof-e2e");
    return result
}

export async function verifyNoirProofBrowser(
    proof: SemaphoreNoirProof,
    noirCompiledCircuit?: CompiledCircuit,
    threads?: number
): Promise<boolean> {
    requireDefined(proof, "proof")
    requireObject(proof, "proof")

    const { merkleTreeDepth, merkleTreeRoot, nullifier, message, scope, proofBytes } = proof

    requireNumber(merkleTreeDepth, "proof.merkleTreeDepth")
    requireString(merkleTreeRoot, "proof.merkleTreeRoot")
    requireString(nullifier, "proof.nullifier")
    requireString(message, "proof.message")
    requireString(scope, "proof.scope")
    requireUint8Array(proofBytes, "proof.proofBytes")

    if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
    }

    // If the Noir circuit has not been passed, it will be automatically downloaded.
    // The circuit is defined by SemaphoreNoirProof.merkleTreeDepth
    let backend: UltraHonkBackend
    try {
        noirCompiledCircuit ??= await maybeGetCompiledNoirCircuit(Project.SEMAPHORE_NOIR, merkleTreeDepth)

        const nrThreads = threads ?? 1
        backend = new UltraHonkBackend(noirCompiledCircuit.bytecode, { threads: nrThreads })
    } catch (err) {
        throw new Error(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
    }

    const proofData = {
        publicInputs: [hash(proof.scope), hash(proof.message), proof.merkleTreeRoot, proof.nullifier],
        proof: proof.proofBytes
    }
    return backend.verifyProof(proofData)
}
