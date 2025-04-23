import { maybeGetCompiledNoirCircuit, Project } from "@zk-kit/artifacts"
import { Group, MerkleProof } from "@semaphore-protocol/group"
import { requireDefined } from "@zk-kit/utils/error-handlers"
import { CompiledCircuit, Noir } from "@noir-lang/noir_js"
import { MAX_DEPTH, MIN_DEPTH } from "@semaphore-protocol/utils/constants"
import { Identity } from "@semaphore-protocol/identity"
import { UltraHonkBackend } from "./ultrahonk"

export type SemaphoreNoirBackend = {
    honkBackend: UltraHonkBackend
    noir: Noir
    merkleTreeDepth: number
}

// init Honk Backend so it's reusable
// UltraHonkBackend is tied to a circuit, be sure to re-initialize when changing merkleTreeDepth
export async function initSemaphoreNoirBackend(
    merkleTreeDepth: number,
    noirCompiledCircuit?: CompiledCircuit,
    threads?: number
): Promise<SemaphoreNoirBackend> {
    if (merkleTreeDepth < MIN_DEPTH || merkleTreeDepth > MAX_DEPTH) {
        throw new TypeError(`The tree depth must be a number between ${MIN_DEPTH} and ${MAX_DEPTH}`)
    }
    try {
        // If the Noir circuit has not been passed, it will be automatically downloaded.
        noirCompiledCircuit ??= await maybeGetCompiledNoirCircuit(Project.SEMAPHORE_NOIR, merkleTreeDepth)
        // Initialize Noir with the compiled circuit
        const noir = new Noir(noirCompiledCircuit)

        const nrThreads = threads ?? 1
        const honkBackend = new UltraHonkBackend(noirCompiledCircuit.bytecode, { threads: nrThreads })
        await honkBackend.instantiate()

        return { honkBackend, noir, merkleTreeDepth }
    } catch (err) {
        throw new TypeError(`Failed to load compiled Noir circuit: ${(err as Error).message}`)
    }
}

// calculate merkleTreeDepth with a group or a merkle proof
export function getMerkleTreeDepth(identity: Identity, groupOrMerkleProof: Group | MerkleProof): number {
    requireDefined(groupOrMerkleProof, "groupOrMerkleProof")

    let merkleProof
    // The second parameter can be either a Merkle proof or a group.
    // If it is a group the Merkle proof will be calculated here.
    if ("siblings" in groupOrMerkleProof) {
        merkleProof = groupOrMerkleProof
    } else {
        const leafIndex = groupOrMerkleProof.indexOf(identity.commitment)
        merkleProof = groupOrMerkleProof.generateMerkleProof(leafIndex)
    }

    // If the merkleTreeDepth is not passed, the length of the merkle proof is used.
    // Note that this value can be smaller than the actual depth of the tree
    const merkleProofLength = merkleProof.siblings.length
    const merkleTreeDepth = merkleProofLength !== 0 ? merkleProofLength : 1

    return merkleTreeDepth
}
