//SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title SemaphoreVerifier contract interface.
interface IVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 merkleTreeDepth
    ) external view returns (bool);
}
