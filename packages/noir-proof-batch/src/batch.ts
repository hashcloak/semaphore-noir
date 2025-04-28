import type { SemaphoreNoirProof } from "@semaphore-protocol/proof"
import { CompiledCircuit, Noir } from "@noir-lang/noir_js"
import path from "path"
import { spawnSync } from "child_process"
import { mkdirSync, readFileSync } from "fs"
import { writeFile, mkdir } from "fs/promises"
import { NoirBatchProof } from "./types"
import hash from "./hash"

// deflattenFields and uint8ArrayToHex come from barretenberg
const uint8ArrayToHex = (buffer: Uint8Array): string => {
    const hex: string[] = []

    buffer.forEach((i) => {
        let h = i.toString(16)
        if (h.length % 2) {
            h = `0${h}`
        }
        hex.push(h)
    })

    return `0x${hex.join("")}`
}

// https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/ts/src/proof/index.ts#L47
// But is not exported in bb.js
export function deflattenFields(flattenedFields: Uint8Array): string[] {
    const publicInputSize = 32
    const chunkedFlattenedPublicInputs: Uint8Array[] = []

    for (let i = 0; i < flattenedFields.length; i += publicInputSize) {
        const publicInput = flattenedFields.slice(i, i + publicInputSize)
        chunkedFlattenedPublicInputs.push(publicInput)
    }

    return chunkedFlattenedPublicInputs.map(uint8ArrayToHex)
}

function runBB(argsArray: any[]) {
    const result = spawnSync("bb", argsArray, { stdio: "inherit" })
    if (result.status !== 0) {
        throw new Error(`bb exited with code ${result.status}`)
    }
}

export default async function batchSemaphoreNoirProofs(
    proofs: SemaphoreNoirProof[],
    // TODO should the vk be added per proof? Rn it assumes all Semaphore proofs are of the same max_depth
    semaphoreCircuitVk: string[], // should be 128 bytes
    // TODO make both circuits optional, so they can be retrieved
    batchLeavesCircuit: CompiledCircuit,
    batchNodesCircuit: CompiledCircuit
): Promise<NoirBatchProof> {
    const tempDir = path.normalize(path.join("./", "semaphore_artifacts"))
    let batchLeavesNoir: Noir
    let batchNodesNoir: Noir

    try {
        // store the compiled circuits locally for bb
        await mkdir(tempDir).catch((err) => {
            if (err.code !== "EEXIST") throw err
        })
        await writeFile(path.join(tempDir, `batch_2_leaves_circuit.json`), JSON.stringify(batchLeavesCircuit as any))
        await writeFile(path.join(tempDir, `batch_2_nodes_circuit.json`), JSON.stringify(batchNodesCircuit as any))

        batchLeavesNoir = new Noir(batchLeavesCircuit)
        batchNodesNoir = new Noir(batchNodesCircuit)
    } catch (err) {
        throw new TypeError(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
    }

    const vkHash = `0x${"0".repeat(64)}`

    // To start: Assume N is a power of 2.
    // STEP 1: Generate the first layer of proofs, combining Semaphore proofs per pair
    const leafLayerProofs: NoirBatchProof[] = []
    const recursion = path.join(tempDir, "recursion")
    mkdirSync(recursion, { recursive: true })

    for (let i = 0; i < proofs.length; i += 2) {
        const proof0 = proofs[i]
        const proof1 = proofs[i + 1]

        const proofAsFields0 = deflattenFields(proof0.proofBytes)
        const publicInputs0 = [
            hash(proof0.scope).toString() as `0x${string}`,
            hash(proof0.message).toString() as `0x${string}`,
            proof0.merkleTreeRoot.toString() as `0x${string}`,
            proof0.nullifier.toString() as `0x${string}`
        ]

        const proofAsFields1 = deflattenFields(proof1.proofBytes)
        const publicInputs1 = [
            hash(proof1.scope).toString() as `0x${string}`,
            hash(proof1.message).toString() as `0x${string}`,
            proof1.merkleTreeRoot.toString() as `0x${string}`,
            proof1.nullifier.toString() as `0x${string}`
        ]

        const { witness } = await batchLeavesNoir.execute({
            sp: [
                {
                    verification_key: semaphoreCircuitVk,
                    proof: proofAsFields0,
                    public_inputs: publicInputs0,
                    key_hash: vkHash
                },
                {
                    verification_key: semaphoreCircuitVk,
                    proof: proofAsFields1,
                    public_inputs: publicInputs1,
                    key_hash: vkHash
                }
            ]
        })
        await writeFile(`${recursion}/witness_${i}.gz`, witness)

        runBB([
            "prove",
            "--output_format",
            "bytes_and_fields",
            "-b",
            `${tempDir}/batch_2_leaves_circuit.json`,
            "-w",
            `${recursion}/witness_${i}.gz`,
            "-o",
            recursion,
            "--recursive"
        ])
        const proofFields = JSON.parse(readFileSync(`${recursion}/proof_fields.json`, "utf-8"))

        leafLayerProofs.push({
            publicInputs: [],
            proofBytes: proofFields
        })
    }

    // recursionCircuitVk is fixed
    const recursionCircuitVk = [
        "0x0000000000000000000000000000000000000000000000000000000000200000",
        "0x0000000000000000000000000000000000000000000000000000000000000010",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000003",
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
        "0x000000000000000000000000000000853793114cc97784c0662f7fb49093b15a",
        "0x000000000000000000000000000000000005db220d982083e5d8fbb5964ab426",
        "0x00000000000000000000000000000041efd0de6aff4ff3c7895cb7101c7a31a1",
        "0x000000000000000000000000000000000025c91f18c4d5a4e1b44eac89a8373a",
        "0x0000000000000000000000000000006cdcb45f8e2fc34ad9a8dbb2c2088acca4",
        "0x0000000000000000000000000000000000212e0cf40c1e663429ad834887b6bc",
        "0x00000000000000000000000000000021a19734b786b054f8b7798fe84075052e",
        "0x000000000000000000000000000000000015baba9110cd7bf6157e312b203437",
        "0x0000000000000000000000000000002db4b48aa7aebcf12a4eff376ca91907e7",
        "0x0000000000000000000000000000000000224dffa2aaeaedc6b6149fa7a4cb2d",
        "0x000000000000000000000000000000da6e92ce2205843e532b31c3346d748b33",
        "0x000000000000000000000000000000000004cb894b27e063af560b46c25aa713",
        "0x000000000000000000000000000000b76ac3dd8f68ad0138d95e5bd666877d0c",
        "0x00000000000000000000000000000000000a9a3d8a12af2e2b80e73f7b4fb1a2",
        "0x00000000000000000000000000000041493046ff7a4d6d8fcbf8208e4eb2233a",
        "0x00000000000000000000000000000000001065db107324d016164ccdd9a93728",
        "0x00000000000000000000000000000046bf3ee4402294368f6b5336044336ddf3",
        "0x00000000000000000000000000000000001b247d3663a44c03704ea7e08f608e",
        "0x0000000000000000000000000000000ca97c4255791a0c1dad0ff4eba3440bb3",
        "0x00000000000000000000000000000000000935ba6c9da3223fa5cb39217ce065",
        "0x000000000000000000000000000000afcd68c0b0e3097570bd9ab388244628b5",
        "0x00000000000000000000000000000000000b542cc196cc8b0eb8b86042ea807f",
        "0x00000000000000000000000000000017f1f77ab3edcf7902cb5260f5dfe22952",
        "0x00000000000000000000000000000000000fd19ff666baf07b4e749b472f7b75",
        "0x000000000000000000000000000000ece661d9ddf8d6ce71e63ee377b120f70f",
        "0x000000000000000000000000000000000017c6d9d50e48678a2ac344538de4c7",
        "0x000000000000000000000000000000ad54bcdd8f21bebc775e9dfb36b9a73d45",
        "0x000000000000000000000000000000000019c51b736e4c5a7d8380246160d19a",
        "0x0000000000000000000000000000003f3b0fca9997b0581d08bea04ddc0752e0",
        "0x0000000000000000000000000000000000212f1f6c8a813551f1e52ec48c11ec",
        "0x0000000000000000000000000000007b6fbb3d28ff034c91c1e68a7eac726185",
        "0x00000000000000000000000000000000000f637990bdbd5adbd912afd325ab84",
        "0x000000000000000000000000000000796ee4dcfaac96d5a23126decc7912a0d0",
        "0x00000000000000000000000000000000002dd763eabd10d073f4b249f0ac9f69",
        "0x000000000000000000000000000000fc4c964e1df2e7329b832525e379351d8a",
        "0x000000000000000000000000000000000024f49b460ae83eee1d323044f1ca9f",
        "0x0000000000000000000000000000000f2f33f7d03d31143e9565c827c5586ca8",
        "0x000000000000000000000000000000000028054cb80059e066f2f4efa92071cd",
        "0x000000000000000000000000000000eebf6061224abe73ddcf1207efe2ce49e1",
        "0x000000000000000000000000000000000010e11931417ce0a6612890b8ee982b",
        "0x000000000000000000000000000000d0ac32ebd9a08132a26175aa89a8f7e639",
        "0x00000000000000000000000000000000002d23ee42c21be324ec226f9c7a84fd",
        "0x000000000000000000000000000000c84f9e50b6b3b146333bffbbdd880cf7b6",
        "0x00000000000000000000000000000000002db48d08acdceae4beb0df6ffac301",
        "0x0000000000000000000000000000009f85538bd81adcf3a21d179c351cd34ccc",
        "0x0000000000000000000000000000000000137a790e4e5fc4e6e3e2c291590498",
        "0x000000000000000000000000000000925336e705dd8a85153954b7f7992a8a0c",
        "0x00000000000000000000000000000000000a6b574aa29f7771b627bd5a5c2b78",
        "0x000000000000000000000000000000fa3e2c735c34d138fe59cbbf7836431d97",
        "0x0000000000000000000000000000000000286835edb3d8659f60690e4b4b44c4",
        "0x000000000000000000000000000000ada5a7ad87f2e52ff76a305a2bf0790a70",
        "0x00000000000000000000000000000000001525b6fba23e02e5e78e1f41b028ae",
        "0x000000000000000000000000000000b13e818265bad80a923ca0eaf38161467f",
        "0x0000000000000000000000000000000000010843239d7b7a2e9c66625f2913fe",
        "0x000000000000000000000000000000fe70ed9011f8bc88590eaa4f5158a4ee57",
        "0x0000000000000000000000000000000000141ce316b7ca52edd89b46aae19ffe",
        "0x00000000000000000000000000000079b8a22dd373d4848de905c1dd528320ba",
        "0x000000000000000000000000000000000021723f776efeb964ff91ac76e63c4b",
        "0x0000000000000000000000000000007d3ec2c8ab38ce9e53252c9bf3c6266305",
        "0x00000000000000000000000000000000001930025d49aa27db7b52aad16d9c30",
        "0x000000000000000000000000000000458657ae33a7da34c092c3837ebd0014d0",
        "0x00000000000000000000000000000000000248ab05faae9973fa1717292832ad",
        "0x0000000000000000000000000000001c43e9a2129968d95fb701d316fc1e7767",
        "0x00000000000000000000000000000000002e3b09e1da086a912a286a4c6a4dff",
        "0x0000000000000000000000000000009d03ae2f9e8f5741b54398002d36f628be",
        "0x00000000000000000000000000000000002acb44e717fff904dc65845d6571bb",
        "0x00000000000000000000000000000036d9aac2a8abda95dc86934cbdae4edf77",
        "0x000000000000000000000000000000000017914e40c463428fa4e860bdf2be5a",
        "0x0000000000000000000000000000003fcab131869553ab7269019a852a6e19d5",
        "0x0000000000000000000000000000000000111337dbd2c760ab3c16b736c3e096",
        "0x000000000000000000000000000000d05cf70547518af7295c0b1665734363c6",
        "0x00000000000000000000000000000000000d8f188d46d4662c6e450723693dab",
        "0x000000000000000000000000000000b2f67a8ab2d56c649c23ead379cae6701a",
        "0x0000000000000000000000000000000000109474fbac03e39a12123247d537b5",
        "0x000000000000000000000000000000656225dbea2977aeaaf8a580fbe3535f83",
        "0x000000000000000000000000000000000003bb08f5ad597bcc784d8866cebfda",
        "0x0000000000000000000000000000005c71ae752a6849552b1cfa147243cf4bb3",
        "0x000000000000000000000000000000000009bb85ad242bfd649cede6fd276c49",
        "0x000000000000000000000000000000d4f0f8d94462a97dd586a70b32aa12bc51",
        "0x0000000000000000000000000000000000063a3fef5f97c2b4291837fb473d6e",
        "0x0000000000000000000000000000007b53f89c7f953bcc775e2bc18209dc9679",
        "0x00000000000000000000000000000000002ab7067253088d36c661bd99c9bd36",
        "0x0000000000000000000000000000000fe074d48f6c99836c769fe43d8ac16fd6",
        "0x000000000000000000000000000000000006f57a8492c43a8ab8d61b828e0001",
        "0x000000000000000000000000000000243cf3e0cfba606d27d5999f4927ff92b3",
        "0x00000000000000000000000000000000001f1156b93b4396e0dac3bd312fdc94",
        "0x000000000000000000000000000000419d9961d76a65ed28914ca5cc3ffd2433",
        "0x0000000000000000000000000000000000116a7935196d39ea9178a285c53a6b",
        "0x000000000000000000000000000000f369409c76a0245d4f389193b554c30065",
        "0x000000000000000000000000000000000023aebc5efc1d0e6d03030b242308fd",
        "0x0000000000000000000000000000000cbfc1214af084c189478e34dc04c77419",
        "0x000000000000000000000000000000000019f38f8e7cf18f375d75db06fca92a",
        "0x0000000000000000000000000000000a771b5bbb501c75790a1a4e2906931045",
        "0x000000000000000000000000000000000015642d62fc17d119ba4afb77ab424e",
        "0x000000000000000000000000000000a5c1396036397af54a729801cc1c37d4e2",
        "0x000000000000000000000000000000000021cea98314ec6efc5f8f1f648f42a7",
        "0x000000000000000000000000000000dd5b4a42e59fe1e447cad24659049d13a7",
        "0x00000000000000000000000000000000001f3bd0ebf0709ac30745d0dafb183c",
        "0x00000000000000000000000000000016c2efd51d298fee5fce4355fc26890195",
        "0x000000000000000000000000000000000005900180ddd1cec6e340c70c9bff6f",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x000000000000000000000000000000c4b6fb9150ed11685a09038ea35070642d",
        "0x0000000000000000000000000000000000007280c5169a0e1f859a500138817e",
        "0x000000000000000000000000000000f7151c97526c14e4531a6b1778adccedf5",
        "0x000000000000000000000000000000000016658259e029bb766fe0d828342f9e"
    ]
    // Now aggregate the proofs recursively. Starting with the leaf pairs
    let currentLayerProofs: NoirBatchProof[] = leafLayerProofs

    // Keep batching node layers until only 1 proof remains
    // This assumes number of initial proofs is a power of 2
    let layer = 1
    while (currentLayerProofs.length > 1) {
        const nextLayerProofs: NoirBatchProof[] = []

        for (let i = 0; i < currentLayerProofs.length; i += 2) {
            const proof0 = currentLayerProofs[i]
            const proof1 = currentLayerProofs[i + 1]

            const { witness } = await batchNodesNoir.execute({
                bp: [
                    {
                        verification_key: recursionCircuitVk,
                        proof: proof0.proofBytes,
                        key_hash: vkHash
                    },
                    {
                        verification_key: recursionCircuitVk,
                        proof: proof1.proofBytes,
                        key_hash: vkHash
                    }
                ]
            })
            await writeFile(`${recursion}/witness_nodes_${layer}_${i}.gz`, witness)

            runBB([
                "prove",
                "--output_format",
                "bytes_and_fields",
                "-b",
                `${tempDir}/batch_2_nodes_circuit.json`,
                "-w",
                `${recursion}/witness_nodes_${layer}_${i}.gz`,
                "-o",
                recursion,
                "--recursive"
            ])
            const proofFields = JSON.parse(readFileSync(`${recursion}/proof_fields.json`, "utf-8"))

            nextLayerProofs.push({
                publicInputs: [],
                proofBytes: proofFields
            })
        }

        // Prepare next loop
        currentLayerProofs = nextLayerProofs
        layer += 1
    }

    // Return the root proof
    // TODO separate the root proof from the other layers and add optional keccak flag to inputs
    const rootBatchProof = currentLayerProofs[0]
    return rootBatchProof
}
