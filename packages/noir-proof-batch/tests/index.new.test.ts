import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { poseidon2 } from "poseidon-lite"
import { SemaphoreNoirProof } from "@semaphore-protocol/proof"
import { mkdir } from "fs/promises"
import path from "path"
import { spawn } from "child_process"
import generateNoirProofForBatching from "../src/generate-proof-noir"
import batchSemaphoreNoirProofs from "../src/batch-new"
import verifyBatchProof from "../src/batch-verify"
import toBigInt from "../src/to-bigint"
import hash from "../src/hash"
import { runBB } from "../src/batch"

const leavesCircuitDir = path.join(__dirname, "../circuits/batch_2_leaves_new")
const nodesCircuitDir = path.join(__dirname, "../circuits/batch_2_nodes_new")
const semCircuitDir = path.join(__dirname, "../../circuits-noir")

const batchLeavesCircuitPath = path.join(leavesCircuitDir, "target/batch_2_leaves.json")
const batchNodesCircuitPath = path.join(nodesCircuitDir, "target/batch_2_nodes.json")
const keccakVkDir = path.join(nodesCircuitDir, "target/keccak")
const defaultVkPath = path.join(nodesCircuitDir, "target/vk")
const keccakVkPath = path.join(keccakVkDir, "vk")

const semaphoreCircuitVk = [
    "0x0000000000000000000000000000000000000000000000000000000000004000",
    "0x0000000000000000000000000000000000000000000000000000000000000014",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000000000000000000000000000004",
    "0x0000000000000000000000000000000000000000000000000000000000000005",
    "0x0000000000000000000000000000000000000000000000000000000000000006",
    "0x0000000000000000000000000000000000000000000000000000000000000007",
    "0x0000000000000000000000000000000000000000000000000000000000000008",
    "0x0000000000000000000000000000000000000000000000000000000000000009",
    "0x000000000000000000000000000000000000000000000000000000000000000a",
    "0x000000000000000000000000000000000000000000000000000000000000000b",
    "0x000000000000000000000000000000000000000000000000000000000000000c",
    "0x000000000000000000000000000000000000000000000000000000000000000d",
    "0x000000000000000000000000000000000000000000000000000000000000000e",
    "0x000000000000000000000000000000000000000000000000000000000000000f",
    "0x0000000000000000000000000000000000000000000000000000000000000010",
    "0x0000000000000000000000000000000000000000000000000000000000000011",
    "0x0000000000000000000000000000000000000000000000000000000000000012",
    "0x0000000000000000000000000000000000000000000000000000000000000013",
    "0x0000000000000000000000000000009e7770219b2c1be4b990decac942d2e1f7",
    "0x000000000000000000000000000000000016989adc3c42760b9cd679227fc69b",
    "0x000000000000000000000000000000e6ef34ee1fd3aa686b81c133f32dd85e00",
    "0x00000000000000000000000000000000001de7d8f229e85f725fd534e25748c8",
    "0x00000000000000000000000000000014b9007af8ebda69a0b048e4ec8e815459",
    "0x000000000000000000000000000000000025732c2265f84b4f7b9c5dcb714fef",
    "0x0000000000000000000000000000002d8b9decf7995cfa1d4e4213135295884d",
    "0x00000000000000000000000000000000001b79c94d312b07c1cb07640d8bbcec",
    "0x0000000000000000000000000000009992996f370b6b3c0b4d0ba35a4e161287",
    "0x00000000000000000000000000000000001887d04a8a1b427273e1aac44f2ebe",
    "0x0000000000000000000000000000005757319b92f3e6ea7cb002a01009b0dddd",
    "0x0000000000000000000000000000000000129e1c77356244a94074799a88f5c4",
    "0x000000000000000000000000000000f713cbe669cb4022c6c33694a084268dbe",
    "0x00000000000000000000000000000000001c14f4547824d606187809906cc4ef",
    "0x00000000000000000000000000000075a5bf7c397ac20caa5fb6c16bddeaf631",
    "0x000000000000000000000000000000000009a84b3d0142a45d122a328b671ee1",
    "0x0000000000000000000000000000004f0ff87a3a62ca29f62fc9cdd7d22208b7",
    "0x00000000000000000000000000000000001cfbc61f6ae5b451e921a7ea29a36e",
    "0x0000000000000000000000000000006d58186bdbe556d72d8dc6e80e912d65a7",
    "0x00000000000000000000000000000000001d8d1d1969c7f2883b07cbe9fdf851",
    "0x00000000000000000000000000000021c4304a084e1fab8711264307d62af386",
    "0x00000000000000000000000000000000002a4d2948163f9eca0de02f3b4d071a",
    "0x0000000000000000000000000000007ae34dcada410788e08ac980ae90ec80e6",
    "0x0000000000000000000000000000000000088c361d22a2d7245429c00313e912",
    "0x0000000000000000000000000000002afc5cac5dabeb8f74a2f89ad33f068fe4",
    "0x0000000000000000000000000000000000038147f7985ab2a8d179a7a764ee62",
    "0x0000000000000000000000000000005c7f68b34721dbdaa9d8f2cfc9f432da95",
    "0x000000000000000000000000000000000024095afc77887b20f8293c4a2602c5",
    "0x000000000000000000000000000000abd797ecb4e18d9de08a2d4c89aba0a900",
    "0x00000000000000000000000000000000000007273a50b686287fe3d0b127a6b9",
    "0x000000000000000000000000000000191ba2e577b7436712e4b59ffed21f4ed9",
    "0x00000000000000000000000000000000001efed5d694445c7de4c172dc1ddc4a",
    "0x000000000000000000000000000000d520fb1648cc600bd3952fb968fe378298",
    "0x000000000000000000000000000000000015fc3acfd6e4be9b7b787e79d1af50",
    "0x000000000000000000000000000000b124556ba49d076dd910bde90d3ddff49c",
    "0x0000000000000000000000000000000000183dcfa0abceab2cd882a82383d0c4",
    "0x0000000000000000000000000000006f2eec0a5a56fcdc1f054721d9c416ced7",
    "0x00000000000000000000000000000000002f0b89de157b89af8798d1c5f38b63",
    "0x000000000000000000000000000000a20f3add6d64f0e14d882d6341d229e6ac",
    "0x000000000000000000000000000000000005e42fd57e89d0ee9540b57d0a0b5c",
    "0x00000000000000000000000000000044182df1a5ab9d77cb4eee06e4e8176ec1",
    "0x00000000000000000000000000000000000a93a4e953c87b7da4c2fa27f63f85",
    "0x000000000000000000000000000000546af4bdcb96b9af82c11dd9ff9869e608",
    "0x000000000000000000000000000000000011193e96df7d70ea1f020fe5c6074c",
    "0x000000000000000000000000000000946be7313fac0d45fd5ba8ec3ed13f77b8",
    "0x000000000000000000000000000000000026ba916e4aab322fb4c462faa9f63e",
    "0x00000000000000000000000000000098e24b5927a89ef4d53f0d2c1c15c69658",
    "0x000000000000000000000000000000000004ca3feb19d28a1527d5b81da5bdf7",
    "0x000000000000000000000000000000cb930ec58400dfb39434c79da3e3c2e6fa",
    "0x00000000000000000000000000000000001e679645e4285ce806f5cf1eb1483e",
    "0x0000000000000000000000000000001016e817a557f0ca8db629a74ac0abfa7a",
    "0x0000000000000000000000000000000000197719a6a9f44750818ec10aa50690",
    "0x000000000000000000000000000000202ca30832a2cbccfe74ba165bd07f6051",
    "0x000000000000000000000000000000000025160df0da9aee2fa3d6f912e294e3",
    "0x000000000000000000000000000000b5b219c1b5166a55edb3de77b42f01fb97",
    "0x0000000000000000000000000000000000035818cb82c5f86fc29588396d28dc",
    "0x000000000000000000000000000000550f475cb776c26a945df026d7707a0e0e",
    "0x0000000000000000000000000000000000116cca3ae2334016ff39b9a0cc60e6",
    "0x0000000000000000000000000000001224407dbc61fe8273303fc2cbc19ec756",
    "0x00000000000000000000000000000000000ac392b7bee5cf703ebdeb838c10e4",
    "0x00000000000000000000000000000047737674e5ac76e6f60eca2665a539992a",
    "0x0000000000000000000000000000000000235f75528e7cc1f901afb5931c46bb",
    "0x0000000000000000000000000000000f8ad48a2d6df3c8dcf379b1f99ff7a4b3",
    "0x000000000000000000000000000000000022a4be358b67ec4fe652ff9cd594f2",
    "0x0000000000000000000000000000006bfe94a7e48e86a71a849343754d281a80",
    "0x0000000000000000000000000000000000200ec2708f6c8178bdd5a7c2f518fb",
    "0x0000000000000000000000000000008164940e7b9e8523381cc5d4d865ae54c0",
    "0x000000000000000000000000000000000002636f68012e85077bda225166fd10",
    "0x000000000000000000000000000000f653b61543bc0bc975843a76f973ffd6aa",
    "0x000000000000000000000000000000000020ab0f8656326a163cabd068b7ed79",
    "0x00000000000000000000000000000004592e584b7dde276d1acb9a59d866fd6d",
    "0x00000000000000000000000000000000000d2f9c7f22d6067a6e08b9dd76b78d",
    "0x0000000000000000000000000000007798ccd1c181918f6d719120cee1d44478",
    "0x00000000000000000000000000000000000615a9b096f352dd12c5236968e41b",
    "0x000000000000000000000000000000735142aa764d1890867032f6b723165bc1",
    "0x00000000000000000000000000000000000690c1f45d73314b8c1044745c2bf0",
    "0x000000000000000000000000000000ff5eee447a207d18c950a2de2bcb9ea894",
    "0x000000000000000000000000000000000003b19a8c1b22e5ae854400083a760a",
    "0x000000000000000000000000000000ed21a7afb6237e9f09866df2eea74b423d",
    "0x000000000000000000000000000000000007d494ce5e2d6e0f366ba3e7fb359f",
    "0x0000000000000000000000000000000a1621f5af9958252a19be22167a3bee5c",
    "0x00000000000000000000000000000000001313fa733d615055266d1716e3b838",
    "0x0000000000000000000000000000006dcdcdc415d62a796e417037b7c2140f23",
    "0x0000000000000000000000000000000000171fd68b9a541cac234ee0164e3608",
    "0x0000000000000000000000000000003cee056cd8653f11fe91bec67f9a1ba501",
    "0x00000000000000000000000000000000000cb15289361c0a0e1b78f25efb7e6f",
    "0x000000000000000000000000000000443f54f12a87c2cf5182f3620fc1944c6d",
    "0x000000000000000000000000000000000029664df9e7f07b4aec2f396f6cde12",
    "0x00000000000000000000000000000073875103abf917a76019cf7bba4da77621",
    "0x0000000000000000000000000000000000070b433d46367e191b9bf40eef28b6",
    "0x000000000000000000000000000000a0af4c7b9ef86fe2480692f5f6dc52534a",
    "0x000000000000000000000000000000000026eccd7100479fc88688e129589197",
    "0x0000000000000000000000000000009fb1952dd9aeab56e182d68b662852e36a",
    "0x00000000000000000000000000000000001d62dc541680650e594af57d090320",
    "0x0000000000000000000000000000008dff03113bc84bd8a1582702c3a51cc8fd",
    "0x0000000000000000000000000000000000150131f285f1648db0d2d85128255b",
    "0x0000000000000000000000000000006f575a60d3c9d50fc277988d94997a5ddb",
    "0x00000000000000000000000000000000000082e0b52e8df94612b14bc2afb9f7",
    "0x000000000000000000000000000000fe073ff12f2bad78b10ae4a1629516a075",
    "0x000000000000000000000000000000000026a696f75adf15d5934d9edad81c9b",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x000000000000000000000000000000f60b523c8e6bdbecdd2c62b3d0404c6cc2",
    "0x00000000000000000000000000000000001156b83823b6add414bae6c772d229",
    "0x000000000000000000000000000000eedf0d4a25697eb4a929802fa16038bdc0",
    "0x000000000000000000000000000000000009be1dd4a929fe8be4cf6ca331094f"
]

async function runNargoCompile(circuitDir: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const nargo = spawn("nargo", ["compile"], {
            cwd: circuitDir,
            stdio: "inherit"
        })

        nargo.on("error", (err) => reject(err))
        nargo.on("close", (code) => {
            if (code !== 0) {
                reject(new Error(`nargo compile failed with exit code ${code}`))
            } else {
                resolve()
            }
        })
    })
}

async function runBBTest(argsArray: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
        const bbProcess = spawn("bb", argsArray, { stdio: "inherit" })

        bbProcess.on("error", (err) => {
            reject(new Error(`Failed to start bb process: ${err.message}`))
        })

        bbProcess.on("close", () => resolve())
    })
}

const allProofs: SemaphoreNoirProof[] = []
const maxProofs = 17

const merkleTreeDepth = 10
const message = 1
const scope = 2

beforeAll(async () => {
    // 1. Compile the circuits using nargo
    await runNargoCompile(leavesCircuitDir)
    await runNargoCompile(nodesCircuitDir)

    // 2. Generate default VK
    await runBBTest([
        "write_vk",
        "-v",
        "--scheme",
        "ultra_honk",
        "-b",
        batchNodesCircuitPath,
        "-o",
        path.join(nodesCircuitDir, "target"),
        "--honk_recursion",
        "1"
    ])

    // 3. Generate keccak VK
    await mkdir(keccakVkDir, { recursive: true })

    await runBBTest([
        "write_vk",
        "-v",
        "--scheme",
        "ultra_honk",
        "--oracle_hash",
        "keccak",
        "-b",
        batchNodesCircuitPath,
        "-o",
        keccakVkDir,
        "--honk_recursion",
        "1"
    ])

    // 4. Generate proofs that can be used in the tests
    const group = new Group()
    const identities: Identity[] = []

    for (let i = 0; i < maxProofs; i += 1) {
        const identity = new Identity(`secret-${i}`)
        identities.push(identity)
        group.addMember(identity.commitment)
    }

    for (const identity of identities) {
        const proof = await generateNoirProofForBatching(identity, group, message, scope, merkleTreeDepth)
        allProofs.push(proof)
    }
}, 600_000)

describe("batchSemaphoreNoirProofs", () => {
    type BatchTestOptions = {
        useKeccak?: boolean
        useCircuitsPaths?: boolean
        useSemVkPath?: boolean
        useBatchVkPath?: boolean
    }

    const runBatchTest = (
        nrProofs: number,
        {
            useKeccak = false,
            useCircuitsPaths = true,
            useSemVkPath = true,
            useBatchVkPath = true
        }: BatchTestOptions = {}
    ) =>
        it(`batches ${nrProofs} proofs${useKeccak ? " with keccak" : ""}${!useSemVkPath ? ", no Semaphore VK" : ""}${!useBatchVkPath ? ", no batch VK" : ""}`, async () => {
            if (useKeccak && !useBatchVkPath) {
                throw new Error("Keccak mode requires useBatchVkPath to be enabled.")
            }
            const proofs = allProofs.slice(0, nrProofs)
            const circuitPath1 = useCircuitsPaths ? batchLeavesCircuitPath : undefined
            const circuitPath2 = useCircuitsPaths ? batchNodesCircuitPath : undefined
            const semVk = useSemVkPath ? semaphoreCircuitVk : undefined
            const { path: proofPath } = await batchSemaphoreNoirProofs(
                proofs,
                semVk,
                circuitPath1,
                circuitPath2,
                useKeccak
            )

            let vkPath: string | undefined
            if (useKeccak) {
                vkPath = keccakVkPath
            } else if (useBatchVkPath) {
                vkPath = defaultVkPath
            }

            const verified = await verifyBatchProof(proofPath, vkPath, useKeccak)
            expect(verified).toBe(true)
        }, 600_000)

    it("Should error if proofs.length < 3", async () => {
        await expect(() => batchSemaphoreNoirProofs(allProofs.slice(0, 2), semaphoreCircuitVk)).rejects.toThrow(
            "At least three Semaphore proofs are required for batching."
        )
    })

    it("Should error if proofs have different merkleTreeDepths", async () => {
        const proofs = [...allProofs.slice(0, 3)]
        const modified = { ...allProofs[3], merkleTreeDepth: 5 }
        proofs.push(modified)

        await expect(() => batchSemaphoreNoirProofs(proofs, semaphoreCircuitVk)).rejects.toThrow(
            "All Semaphore proofs must have the same merkleTreeDepth."
        )
    })

    describe("runBB", () => {
        it("fails if bb command fails", async () => {
            await expect(runBB(["prove", "--bad-flag"])).rejects.toThrow(/bb failed/)
        })
    })

    runBatchTest(4)
    runBatchTest(4, { useKeccak: true })
    runBatchTest(6, { useSemVkPath: false })
    // TODO - these two tests are failing since we haven't updated snark-artifact
    // runBatchTest(7, { useBatchVkPath: false })
    // runBatchTest(8, { useCircuitsPaths: false })
    runBatchTest(9)
    runBatchTest(15)
    runBatchTest(16)
    runBatchTest(17)
})

describe("verifyBatchProof", () => {
    it("verifies a valid proof", async () => {
        const proofs = allProofs.slice(0, 4)
        const { path: proofPath } = await batchSemaphoreNoirProofs(
            proofs,
            semaphoreCircuitVk,
            batchLeavesCircuitPath,
            batchNodesCircuitPath
        )

        const verified = await verifyBatchProof(proofPath, defaultVkPath)
        expect(verified).toBe(true)
    }, 600_000)

    it("returns false with incorrect VK", async () => {
        const proofs = allProofs.slice(0, 4)
        const { path: proofPath } = await batchSemaphoreNoirProofs(
            proofs,
            semaphoreCircuitVk,
            batchLeavesCircuitPath,
            batchNodesCircuitPath
        )

        const verified = await verifyBatchProof(proofPath, keccakVkPath) // wrong vk for this proof
        expect(verified).toBe(false)
    }, 600_000)
})

describe("generateNoirProofForBatching", () => {
    const identity = new Identity("test-secret")
    const group = new Group([1n, 2n, identity.commitment])
    const depth = 10
    const msg = "Hello world"

    it("Should generate a valid proof with default circuit path", async () => {
        const proof = await generateNoirProofForBatching(identity, group, msg, scope, depth)

        const expectedNullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        expect(typeof proof).toBe("object")
        expect(proof.merkleTreeDepth).toBe(depth)
        expect(proof.merkleTreeRoot).toBe(group.root.toString())
        expect(BigInt(proof.nullifier)).toBe(expectedNullifier)
        expect(proof.message).toBe(toBigInt(msg).toString())
        expect(proof.scope).toBe(toBigInt(scope).toString())
        expect(proof.proofBytes).toBeInstanceOf(Uint8Array)
    }, 80000)

    it("Should generate a valid proof with passed on circuit path", async () => {
        await runNargoCompile(semCircuitDir)
        const merkleProof = group.generateMerkleProof(2)
        merkleProof.siblings = [...merkleProof.siblings, ...Array(10 - merkleProof.siblings.length).fill(0n)]

        const proof = await generateNoirProofForBatching(
            identity,
            merkleProof,
            msg,
            scope,
            undefined,
            `${semCircuitDir}/target/circuit.json`
        )
        const expectedNullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        expect(typeof proof).toBe("object")
        expect(proof.message).toBe(toBigInt(msg).toString())
        expect(proof.scope).toBe(toBigInt(scope).toString())
        expect(BigInt(proof.nullifier)).toBe(expectedNullifier)
    }, 80000)

    it("Should generate a valid proof if circuit path is not provided", async () => {
        const proof = await generateNoirProofForBatching(identity, group, msg, scope)
        const expectedNullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        expect(typeof proof).toBe("object")
        expect(proof.message).toBe(toBigInt(msg).toString())
        expect(proof.scope).toBe(toBigInt(scope).toString())
        expect(BigInt(proof.nullifier)).toBe(expectedNullifier)
    }, 80000)

    it("Should Error if instantiating Noir fails because of invalid circuit", async () => {
        await runNargoCompile(semCircuitDir)

        await expect(
            generateNoirProofForBatching(identity, group, msg, scope, undefined, `${semCircuitDir}`)
        ).rejects.toThrow("Failed to instantiate Noir")
    }, 80000)

    it("Should generate a valid proof when passing a Merkle proof instead of a group", async () => {
        const proof = await generateNoirProofForBatching(identity, group.generateMerkleProof(2), msg, scope)
        const expectedNullifier = poseidon2([hash(toBigInt(scope)), identity.secretScalar])

        expect(typeof proof).toBe("object")
        expect(proof.message).toBe(toBigInt(msg).toString())
        expect(proof.scope).toBe(toBigInt(scope).toString())
        expect(BigInt(proof.nullifier)).toBe(expectedNullifier)
    }, 80000)

    it("Should error if identity is not in the group", async () => {
        const outsider = new Identity("outsider")
        const newGroup = new Group()
        newGroup.addMember(new Identity("someone-else").commitment)

        await expect(generateNoirProofForBatching(outsider, newGroup, msg, scope, depth)).rejects.toThrow(
            "does not exist"
        )
    }, 80000)

    it("Should error if merkleTreeDepth is out of bounds", async () => {
        await expect(generateNoirProofForBatching(identity, group, msg, scope, 999)).rejects.toThrow(
            "tree depth must be a number between"
        )
    }, 80000)

    it("Should default to merkleTreeDepth = 1 if Merkle proof has length 0", async () => {
        const singleMemberGroup = new Group([identity.commitment])
        const merkleProof = singleMemberGroup.generateMerkleProof(0)

        expect(merkleProof.siblings).toHaveLength(0)

        const proof = await generateNoirProofForBatching(identity, merkleProof, msg, scope)

        expect(proof.merkleTreeDepth).toBe(1)
    })
})

describe("toBigInt", () => {
    it("throws TypeError for invalid non-string input", () => {
        const invalidValue = { not: "convertible" }

        expect(() => toBigInt(invalidValue as any)).toThrow(TypeError)
    })
})
