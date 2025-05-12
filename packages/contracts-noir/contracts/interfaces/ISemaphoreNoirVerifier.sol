//SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title SemaphoreNoirVerifier contract interface.
interface IVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 merkleTreeDepth,
        bool batch
    ) external returns (bool);
}
