import { BackendOptions, Barretenberg, ProofData, RawBuffer, splitHonkProof, reconstructHonkProof } from "@aztec/bb.js"
import { decompressSync as gunzip } from "fflate"

/**
 * Options for the UltraHonkBackend.
 */
export type UltraHonkBackendOptions = {
    /**Selecting this option will use the keccak hash function instead of poseidon
     * when generating challenges in the proof.
     * Use this when you want to verify the created proof on an EVM chain.
     */
    keccak: boolean
}

export type CircuitOptions = {
    /** @description Whether to produce SNARK friendly proofs */
    recursive: boolean
}

export type ProofDataForRecursion = {
    /** @description Public inputs of a proof */
    publicInputs: string[]
    /** @description An byte array representing the proof */
    proof: string[]
}

/**
 * This is a modified verson of UltraHonkBackend from @aztec/bb.js
 * Most of the logic stays the same, except that numPublicInputs and vkBuf are added
 * as parameters of generateProof() and verifyProof(). So the verification keys
 * can be pre-calculated and reused.
 */
export class UltraHonkBackend {
    // These type assertions are used so that we don't
    // have to initialize `api` in the constructor.
    // These are initialized asynchronously in the `init` function,
    // constructors cannot be asynchronous which is why we do this.

    protected api!: Barretenberg
    protected acirUncompressedBytecode: Uint8Array

    constructor(
        acirBytecode: string,
        protected backendOptions: BackendOptions = { threads: 1 },
        protected circuitOptions: CircuitOptions = { recursive: false }
    ) {
        this.acirUncompressedBytecode = acirToUint8Array(acirBytecode)
    }
    /** @ignore */
    async instantiate(): Promise<void> {
        if (!this.api) {
            const api = await Barretenberg.new(this.backendOptions)
            const honkRecursion = true
            await api.acirInitSRS(this.acirUncompressedBytecode, this.circuitOptions.recursive, honkRecursion)

            // We don't init a proving key here in the Honk API
            // await api.acirInitProvingKey(this.acirComposer, this.acirUncompressedBytecode);
            this.api = api
        }
    }

    async generateProof(
        compressedWitness: Uint8Array,
        options?: UltraHonkBackendOptions,
        numPublicInputs?: number
    ): Promise<ProofData> {
        await this.instantiate()

        const proveUltraHonk = options?.keccak
            ? this.api.acirProveUltraKeccakHonk.bind(this.api)
            : this.api.acirProveUltraHonk.bind(this.api)

        const proofWithPublicInputs = await proveUltraHonk(
            this.acirUncompressedBytecode,
            this.circuitOptions.recursive,
            gunzip(compressedWitness)
        )

        if (!numPublicInputs) {
            // Write VK to get the number of public inputs
            const writeVKUltraHonk = options?.keccak
                ? this.api.acirWriteVkUltraKeccakHonk.bind(this.api)
                : this.api.acirWriteVkUltraHonk.bind(this.api)

            const vk = await writeVKUltraHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive)
            const vkAsFields = await this.api.acirVkAsFieldsUltraHonk(new RawBuffer(vk))

            // Item at index 1 in VK is the number of public inputs
            numPublicInputs = Number(vkAsFields[1].toString())
        }

        const { proof, publicInputs: publicInputsBytes } = splitHonkProof(proofWithPublicInputs, numPublicInputs)
        const publicInputs = deflattenFields(publicInputsBytes)

        return { proof, publicInputs }
    }

    // async generateProofForRecursiveAggregation(
    //     compressedWitness: Uint8Array,
    //     options?: UltraHonkBackendOptions
    // ): Promise<ProofDataForRecursion> {
    //     await this.instantiate()

    //     const proveUltraHonk = options?.keccak
    //         ? this.api.acirProveUltraKeccakHonk.bind(this.api)
    //         : this.api.acirProveUltraHonk.bind(this.api)

    //     const proofWithPublicInputs = await proveUltraHonk(
    //         this.acirUncompressedBytecode,
    //         this.circuitOptions.recursive,
    //         gunzip(compressedWitness)
    //     )
    //     // Write VK to get the number of public inputs
    //     const writeVKUltraHonk = options?.keccak
    //         ? this.api.acirWriteVkUltraKeccakHonk.bind(this.api)
    //         : this.api.acirWriteVkUltraHonk.bind(this.api)

    //     const vk = await writeVKUltraHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive)
    //     const vkAsFields = await this.api.acirVkAsFieldsUltraHonk(new RawBuffer(vk))

    //     // some public inputs are handled specially
    //     const numKZGAccumulatorFieldElements = 16
    //     const publicInputsSizeIndex = 1 // index into VK for numPublicInputs
    //     const numPublicInputs = Number(vkAsFields[publicInputsSizeIndex].toString()) - numKZGAccumulatorFieldElements

    //     const { proof: proofBytes, publicInputs: publicInputsBytes } = splitHonkProof(
    //         proofWithPublicInputs,
    //         numPublicInputs
    //     )

    //     const publicInputs = deflattenFields(publicInputsBytes)
    //     const proof = deflattenFields(proofBytes)

    //     return { proof, publicInputs }
    // }

    async verifyProof(proofData: ProofData, options?: UltraHonkBackendOptions, vkBuf?: Uint8Array): Promise<boolean> {
        await this.instantiate()

        const proof = reconstructHonkProof(flattenFieldsAsArray(proofData.publicInputs), proofData.proof)

        const verifyUltraHonk = options?.keccak
            ? this.api.acirVerifyUltraKeccakHonk.bind(this.api)
            : this.api.acirVerifyUltraHonk.bind(this.api)

        if (!vkBuf) {
            const writeVkUltraHonk = options?.keccak
                ? this.api.acirWriteVkUltraKeccakHonk.bind(this.api)
                : this.api.acirWriteVkUltraHonk.bind(this.api)
            vkBuf = await writeVkUltraHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive)
        }

        return await verifyUltraHonk(proof, new RawBuffer(vkBuf))
    }

    // async getVerificationKey(options?: UltraHonkBackendOptions): Promise<Uint8Array> {
    //     await this.instantiate()
    //     return options?.keccak
    //         ? await this.api.acirWriteVkUltraKeccakHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive)
    //         : await this.api.acirWriteVkUltraHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive)
    // }

    // /** @description Returns a solidity verifier */
    // async getSolidityVerifier(vk?: Uint8Array): Promise<string> {
    //     await this.instantiate()
    //     const vkBuf =
    //         vk ?? (await this.api.acirWriteVkUltraHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive))
    //     return await this.api.acirHonkSolidityVerifier(this.acirUncompressedBytecode, new RawBuffer(vkBuf))
    // }

    // // TODO(https://github.com/noir-lang/noir/issues/5661): Update this to handle Honk recursive aggregation in the browser once it is ready in the backend itself
    // async generateRecursiveProofArtifacts(
    //     // eslint-disable-next-line @typescript-eslint/no-unused-vars
    //     _proof: Uint8Array,
    //     // eslint-disable-next-line @typescript-eslint/no-unused-vars
    //     _numOfPublicInputs: number
    // ): Promise<{ proofAsFields: string[]; vkAsFields: string[]; vkHash: string }> {
    //     await this.instantiate()
    //     // TODO(https://github.com/noir-lang/noir/issues/5661): This needs to be updated to handle recursive aggregation.
    //     // There is still a proofAsFields method but we could consider getting rid of it as the proof itself
    //     // is a list of field elements.
    //     // UltraHonk also does not have public inputs directly prepended to the proof and they are still instead
    //     // inserted at an offset.
    //     // const proof = reconstructProofWithPublicInputs(proofData);
    //     // const proofAsFields = (await this.api.acirProofAsFieldsUltraHonk(proof)).slice(numOfPublicInputs);

    //     // TODO: perhaps we should put this in the init function. Need to benchmark
    //     // TODO how long it takes.
    //     const vkBuf = await this.api.acirWriteVkUltraHonk(this.acirUncompressedBytecode, this.circuitOptions.recursive)
    //     const vk = await this.api.acirVkAsFieldsUltraHonk(vkBuf)

    //     return {
    //         // TODO(https://github.com/noir-lang/noir/issues/5661)
    //         proofAsFields: [],
    //         vkAsFields: vk.map((vk) => vk.toString()),
    //         // We use an empty string for the vk hash here as it is unneeded as part of the recursive artifacts
    //         // The user can be expected to hash the vk inside their circuit to check whether the vk is the circuit
    //         // they expect
    //         vkHash: ""
    //     }
    // }

    // async destroy(): Promise<void> {
    //     if (!this.api) {
    //         return
    //     }
    //     await this.api.destroy()
    // }
}

// Converts bytecode from a base64 string to a Uint8Array
function acirToUint8Array(base64EncodedBytecode: string): Uint8Array {
    const compressedByteCode = base64Decode(base64EncodedBytecode)
    return gunzip(compressedByteCode)
}

// Since this is a simple function, we can use feature detection to
// see if we are in the nodeJs environment or the browser environment.
function base64Decode(input: string): Uint8Array {
    if (typeof Buffer !== "undefined") {
        // Node.js environment
        const b = Buffer.from(input, "base64")
        return new Uint8Array(b.buffer, b.byteOffset, b.byteLength)
    } else if (typeof atob === "function") {
        // Browser environment
        return Uint8Array.from(atob(input), (c) => c.charCodeAt(0))
    } else {
        throw new Error("No implementation found for base64 decoding.")
    }
}

export function flattenFieldsAsArray(fields: string[]): Uint8Array {
    const flattenedPublicInputs = fields.map(hexToUint8Array)
    return flattenUint8Arrays(flattenedPublicInputs)
}

function flattenUint8Arrays(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((acc, val) => acc + val.length, 0)
    const result = new Uint8Array(totalLength)

    let offset = 0
    for (const arr of arrays) {
        result.set(arr, offset)
        offset += arr.length
    }

    return result
}

function hexToUint8Array(hex: string): Uint8Array {
    const sanitisedHex = BigInt(hex).toString(16).padStart(64, "0")

    const len = sanitisedHex.length / 2
    const u8 = new Uint8Array(len)

    let i = 0
    let j = 0
    while (i < len) {
        u8[i] = parseInt(sanitisedHex.slice(j, j + 2), 16)
        i += 1
        j += 2
    }

    return u8
}

export function deflattenFields(flattenedFields: Uint8Array): string[] {
    const publicInputSize = 32
    const chunkedFlattenedPublicInputs: Uint8Array[] = []

    for (let i = 0; i < flattenedFields.length; i += publicInputSize) {
        const publicInput = flattenedFields.slice(i, i + publicInputSize)
        chunkedFlattenedPublicInputs.push(publicInput)
    }

    return chunkedFlattenedPublicInputs.map(uint8ArrayToHex)
}

function uint8ArrayToHex(buffer: Uint8Array): string {
    const hex: string[] = []

    buffer.forEach(function (i) {
        let h = i.toString(16)
        if (h.length % 2) {
            h = "0" + h
        }
        hex.push(h)
    })

    return "0x" + hex.join("")
}
