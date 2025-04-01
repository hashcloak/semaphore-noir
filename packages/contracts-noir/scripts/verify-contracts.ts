import { isSupportedNetwork } from "@semaphore-protocol/utils"
import { hardhatArguments, run } from "hardhat"
import { getDeployedContractAddress } from "./utils"

async function verify(address: string, constructorArguments?: any[]): Promise<void> {
    try {
        await run("verify:verify", {
            address,
            constructorArguments
        })
    } catch (error) {
        console.error(error)
    }
}

async function main() {
    const { network } = hardhatArguments

    if (!network || !isSupportedNetwork(network)) {
        throw Error(`Network '${network}' is not supported`)
    }

    const semaphoreNoirVerifierAddress = getDeployedContractAddress(network, "SemaphoreNoirVerifier")
    const poseidonT3Address = getDeployedContractAddress(network, "PoseidonT3")
    const semaphoreAddress = getDeployedContractAddress(network, "Semaphore")

    await verify(semaphoreNoirVerifierAddress)
    await verify(poseidonT3Address)
    await verify(semaphoreAddress, [semaphoreNoirVerifierAddress])
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error)
        process.exit(1)
    })
