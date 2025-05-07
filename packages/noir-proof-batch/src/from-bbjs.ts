/* istanbul ignore file */

// deflattenFields and uint8ArrayToHex come from barretenberg
// https://github.com/AztecProtocol/aztec-packages/blob/v0.82.2/barretenberg/ts/src/proof/index.ts#L93
// But they are not exported in bb.js
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

// Converts byte array to array of (Noir) fields in hex format
// https://github.com/AztecProtocol/aztec-packages/blob/v0.82.2/barretenberg/ts/src/proof/index.ts#L63
export function deflattenFields(flattenedFields: Uint8Array): string[] {
    const publicInputSize = 32
    const chunkedFlattenedPublicInputs: Uint8Array[] = []

    for (let i = 0; i < flattenedFields.length; i += publicInputSize) {
        const publicInput = flattenedFields.slice(i, i + publicInputSize)
        chunkedFlattenedPublicInputs.push(publicInput)
    }

    return chunkedFlattenedPublicInputs.map(uint8ArrayToHex)
}

// Functionality from https://github.com/AztecProtocol/aztec-packages/blob/v0.82.2/barretenberg/ts/src/proof/index.ts#L107
// That is not exported in their module
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

// https://github.com/AztecProtocol/aztec-packages/blob/v0.82.2/barretenberg/ts/src/proof/index.ts#L80
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

// https://github.com/AztecProtocol/aztec-packages/blob/v0.82.2/barretenberg/ts/src/proof/index.ts#L75
export function flattenFieldsAsArray(fields: string[]): Uint8Array {
    const flattenedPublicInputs = fields.map(hexToUint8Array)
    return flattenUint8Arrays(flattenedPublicInputs)
}
