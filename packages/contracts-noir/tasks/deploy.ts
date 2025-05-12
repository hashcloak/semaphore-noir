import { SupportedNetwork } from "@semaphore-protocol/utils"
import { task, types } from "hardhat/config"
import { deploy, saveDeployedContracts } from "../scripts/utils"

task("deploy", "Deploy a Semaphore contract")
    .addOptionalParam<string>("verifier", "Verifier contract address", undefined, types.string)
    .addOptionalParam<string>("poseidon", "Poseidon library address", undefined, types.string)
    .addOptionalParam<string>("honkvk", "Honk Verification key library address", undefined, types.string)
    .addOptionalParam<string>(
        "vkpt1",
        "Verification key points library address for depth <= 16",
        undefined,
        types.string
    )
    .addOptionalParam<string>(
        "vkpt2",
        "Verification key points library address for depth > 16",
        undefined,
        types.string
    )
    .addOptionalParam<boolean>("logs", "Print the logs", true, types.boolean)
    .setAction(
        async (
            {
                logs,
                verifier: semaphoreNoirVerifierAddress,
                poseidon: poseidonT3Address,
                honkvk: honkVkAddress,
                vkpt1: honkVkPoint1,
                vkpt2: honkVkPoint2
            },
            { ethers, hardhatArguments }
        ): Promise<any> => {
            const startBlock = await ethers.provider.getBlockNumber()

            if (!honkVkPoint1) {
                honkVkPoint1 = await deploy(ethers, "SemaphoreVerifierKeyPts1", hardhatArguments.network)

                if (logs) {
                    console.info(`SemaphoreVerifierKeyPts1 library has been deployed to: ${honkVkPoint1}`)
                }
            }
            if (!honkVkPoint2) {
                honkVkPoint2 = await deploy(ethers, "SemaphoreVerifierKeyPts2", hardhatArguments.network)

                if (logs) {
                    console.info(`SemaphoreVerifierKeyPts2 library has been deployed to: ${honkVkPoint2}`)
                }
            }

            if (!honkVkAddress) {
                honkVkAddress = await deploy(ethers, "HonkVerificationKey", hardhatArguments.network, undefined, {
                    libraries: {
                        SemaphoreVerifierKeyPts1: honkVkPoint1,
                        SemaphoreVerifierKeyPts2: honkVkPoint2
                    }
                })

                if (logs) {
                    console.info(`HonkVerificationKey library has been deployed to: ${honkVkAddress}`)
                }
            }

            if (!semaphoreNoirVerifierAddress) {
                semaphoreNoirVerifierAddress = await deploy(
                    ethers,
                    "SemaphoreNoirVerifier",
                    hardhatArguments.network,
                    undefined,
                    {
                        libraries: {
                            HonkVerificationKey: honkVkAddress
                        }
                    }
                )

                if (logs) {
                    console.info(`SemaphoreNoirVerifier contract has been deployed to: ${semaphoreNoirVerifierAddress}`)
                }
            }

            if (!poseidonT3Address) {
                poseidonT3Address = await deploy(ethers, "PoseidonT3", hardhatArguments.network)

                if (logs) {
                    console.info(`PoseidonT3 library has been deployed to: ${poseidonT3Address}`)
                }
            }

            const semaphoreAddress = await deploy(
                ethers,
                "SemaphoreNoir",
                hardhatArguments.network,
                [semaphoreNoirVerifierAddress],
                {
                    libraries: {
                        PoseidonT3: poseidonT3Address
                    }
                }
            )

            if (logs) {
                console.info(`Semaphore Noir contract has been deployed to: ${semaphoreAddress}`)
            }

            saveDeployedContracts(
                [
                    {
                        name: "SemaphoreNoirVerifierKeyPts1",
                        address: honkVkPoint1,
                        startBlock
                    },
                    {
                        name: "SemaphoreNoirVerifierKeyPts2",
                        address: honkVkPoint2,
                        startBlock
                    },
                    {
                        name: "HonkVerificationKey",
                        address: honkVkAddress,
                        startBlock
                    },
                    {
                        name: "SemaphoreNoirVerifier",
                        address: semaphoreNoirVerifierAddress,
                        startBlock
                    },
                    {
                        name: "PoseidonT3",
                        address: poseidonT3Address,
                        startBlock
                    },
                    {
                        name: "SemaphoreNoir",
                        address: semaphoreAddress,
                        startBlock
                    }
                ],
                hardhatArguments.network as SupportedNetwork
            )

            return {
                semaphore: await ethers.getContractAt("SemaphoreNoir", semaphoreAddress),
                verifierAddress: semaphoreNoirVerifierAddress,
                poseidonAddress: poseidonT3Address,
                semaphoreVK1: honkVkPoint1,
                semaphoreVK2: honkVkPoint2,
                honkVerificationKey: honkVkAddress
            }
        }
    )
