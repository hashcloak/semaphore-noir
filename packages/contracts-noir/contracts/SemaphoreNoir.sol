// SPDX-License-Identifier: MIT
pragma solidity >=0.8.23 <=0.8.28;

import {ISemaphore} from "./interfaces/ISemaphoreNoir.sol";
import {IVerifier} from "./interfaces/ISemaphoreNoirVerifier.sol";
import {SemaphoreGroups} from "./base/SemaphoreGroups.sol";
import {MIN_DEPTH, MAX_DEPTH} from "./base/Constants.sol";

/// @title SemaphoreNoir
/// @dev This contract uses the Semaphore base contracts to provide a complete service
/// to allow admins to create and manage groups and their members to verify Semaphore proofs
/// Group admins can add, update or remove group members, and can be an Ethereum account or a smart contract.
/// This contract also assigns each new Merkle tree generated with a new root a duration (or an expiry)
/// within which the proofs generated with that root can be validated.
contract SemaphoreNoir is ISemaphore, SemaphoreGroups {
    uint256 constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IVerifier public verifier;

    /// @dev Gets a group id and returns the group parameters.
    mapping(uint256 => Group) public groups;

    /// @dev Counter to assign an incremental id to the groups.
    /// This counter is used to keep track of the number of groups created.
    uint256 public groupCounter;

    /// @dev Initializes the Semaphore Noir verifier used to verify the user's ZK proofs.
    /// @param _verifier: Semaphore Noir verifier addresse.
    constructor(IVerifier _verifier) {
        verifier = _verifier;
    }

    /// @dev See {SemaphoreGroups-_createGroup}.
    function createGroup() external override returns (uint256 groupId) {
        groupId = groupCounter++;
        _createGroup(groupId, msg.sender);

        groups[groupId].merkleTreeDuration = 1 hours;
    }

    /// @dev See {SemaphoreGroups-_createGroup}.
    function createGroup(address admin) external override returns (uint256 groupId) {
        groupId = groupCounter++;
        _createGroup(groupId, admin);

        groups[groupId].merkleTreeDuration = 1 hours;
    }

    /// @dev See {ISemaphore-createGroup}.
    function createGroup(address admin, uint256 merkleTreeDuration) external override returns (uint256 groupId) {
        groupId = groupCounter++;
        _createGroup(groupId, admin);

        groups[groupId].merkleTreeDuration = merkleTreeDuration;
    }

    /// @dev See {SemaphoreGroups-_updateGroupAdmin}.
    function updateGroupAdmin(uint256 groupId, address newAdmin) external override {
        _updateGroupAdmin(groupId, newAdmin);
    }

    /// @dev See {SemaphoreGroups- acceptGroupAdmin}.
    function acceptGroupAdmin(uint256 groupId) external override {
        _acceptGroupAdmin(groupId);
    }

    /// @dev See {ISemaphore-updateGroupMerkleTreeDuration}.
    function updateGroupMerkleTreeDuration(
        uint256 groupId,
        uint256 newMerkleTreeDuration
    ) external override onlyGroupAdmin(groupId) {
        uint256 oldMerkleTreeDuration = groups[groupId].merkleTreeDuration;

        groups[groupId].merkleTreeDuration = newMerkleTreeDuration;

        emit GroupMerkleTreeDurationUpdated(groupId, oldMerkleTreeDuration, newMerkleTreeDuration);
    }

    /// @dev See {SemaphoreGroups-_addMember}.
    function addMember(uint256 groupId, uint256 identityCommitment) external override {
        uint256 merkleTreeRoot = _addMember(groupId, identityCommitment);

        groups[groupId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev See {SemaphoreGroups-_addMembers}.
    function addMembers(uint256 groupId, uint256[] calldata identityCommitments) external override {
        uint256 merkleTreeRoot = _addMembers(groupId, identityCommitments);

        groups[groupId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev See {SemaphoreGroups-_updateMember}.
    function updateMember(
        uint256 groupId,
        uint256 identityCommitment,
        uint256 newIdentityCommitment,
        uint256[] calldata merkleProofSiblings
    ) external override {
        uint256 merkleTreeRoot = _updateMember(groupId, identityCommitment, newIdentityCommitment, merkleProofSiblings);

        groups[groupId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev See {SemaphoreGroups-_removeMember}.
    function removeMember(
        uint256 groupId,
        uint256 identityCommitment,
        uint256[] calldata merkleProofSiblings
    ) external override {
        uint256 merkleTreeRoot = _removeMember(groupId, identityCommitment, merkleProofSiblings);

        groups[groupId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev See {ISemaphore-validateProof}.
    function validateProof(uint256 groupId, SemaphoreNoirProof calldata proof) external override {
        // The function will revert if the nullifier that is part of the proof,
        // was already used inside the group with id groupId.
        if (groups[groupId].nullifiers[proof.nullifier]) {
            revert Semaphore__YouAreUsingTheSameNullifierTwice();
        }

        // The function will revert if the proof is not verified successfully.
        if (!verifyProof(groupId, proof)) {
            revert Semaphore__InvalidProof();
        }

        // Saves the nullifier so that it cannot be used again to successfully verify a proof
        // that is part of the group with id groupId.
        groups[groupId].nullifiers[proof.nullifier] = true;

        emit ProofValidated(
            groupId,
            proof.merkleTreeDepth,
            proof.merkleTreeRoot,
            proof.nullifier,
            proof.message,
            proof.scope,
            proof.proofBytes
        );
    }

    /// @dev See {ISemaphore-verifyProof}.
    function verifyProof(
        uint256 groupId,
        SemaphoreNoirProof calldata proof
    ) public view override onlyExistingGroup(groupId) returns (bool) {
        // The function will revert if the Merkle tree depth is not supported.
        if (proof.merkleTreeDepth < MIN_DEPTH || proof.merkleTreeDepth > MAX_DEPTH) {
            revert Semaphore__MerkleTreeDepthIsNotSupported();
        }

        // Gets the number of leaves in the Incremental Merkle Tree that represents the group
        // with id groupId which is the same as the number of members in the group groupId.
        uint256 merkleTreeSize = getMerkleTreeSize(groupId);

        // The function will revert if there are no members in the group.
        if (merkleTreeSize == 0) {
            revert Semaphore__GroupHasNoMembers();
        }

        // Gets the Merkle root of the Incremental Merkle Tree that represents the group with id groupId.
        uint256 currentMerkleTreeRoot = getMerkleTreeRoot(groupId);

        // A proof could have used an old Merkle tree root.
        // https://github.com/semaphore-protocol/semaphore/issues/98
        if (proof.merkleTreeRoot != currentMerkleTreeRoot) {
            uint256 merkleRootCreationDate = groups[groupId].merkleRootCreationDates[proof.merkleTreeRoot];
            uint256 merkleTreeDuration = groups[groupId].merkleTreeDuration;

            if (merkleRootCreationDate == 0) {
                revert Semaphore__MerkleTreeRootIsNotPartOfTheGroup();
            }

            if (block.timestamp > merkleRootCreationDate + merkleTreeDuration) {
                revert Semaphore__MerkleTreeRootIsExpired();
            }
        }
        bytes32[] memory publicInput = new bytes32[](4);
        publicInput[0] = bytes32(_hash(proof.scope));
        publicInput[1] = bytes32(_hash(proof.message));
        publicInput[2] = bytes32(proof.merkleTreeRoot);
        publicInput[3] = bytes32(proof.nullifier);

        return verifier.verify(proof.proofBytes, publicInput, proof.merkleTreeDepth, false);
    }

    function validateBatchedProof(
        uint256[] calldata groupIds,
        SemaphoreNoirBatchedProof calldata proof
    ) public onlyExistingGroups(groupIds) returns (bool) {
        require(proof.nullifiers.length == groupIds.length, "Mismatched groupIds and nullifiers length");
        // The function will revert if the nullifier that is part of the proof,
        // was already used inside the group with id groupId.
        for (uint256 i = 0; i < groupIds.length; ++i) {
            if (groups[groupIds[i]].nullifiers[proof.nullifiers[i]]) {
                revert Semaphore__YouAreUsingTheSameNullifierTwice();
            }
        }

        // Also revert if there are double nullifiers within this batched group
        for (uint256 i = 0; i < proof.nullifiers.length; i++) {
            for (uint256 j = i + 1; j < proof.nullifiers.length; j++) {
                if (proof.nullifiers[i] == proof.nullifiers[j]) {
                    revert Semaphore__YouAreUsingTheSameNullifierTwice();
                }
            }
        }

        // The function will revert if the proof is not verified successfully.
        if (!verifyBatchedProof(groupIds, proof)) {
            revert Semaphore__InvalidProof();
        }

        // Saves the nullifier so that it cannot be used again to successfully verify a proof
        // that is part of the group with id groupId.
        for (uint256 i = 0; i < groupIds.length; i++) {
            groups[groupIds[i]].nullifiers[proof.nullifiers[i]] = true;
        }
        emit BatchedProofValidated(
            groupIds,
            proof.nullifiers,
            proof.messages,
            proof.scopes,
            uint256(proof.publicInputs[0]),
            proof.proofBytes
        );
        return true;
    }

    function verifyBatchedProof(
        uint256[] calldata groupIds,
        SemaphoreNoirBatchedProof calldata proof
    ) public view onlyExistingGroups(groupIds) returns (bool) {
        // create an array of hashed public inputs of proofs
        uint256[] memory inputHashes;
        uint256 proofLength = proof.nullifiers.length;
        if (proofLength % 2 == 0) {
            inputHashes = new uint256[](proofLength / 2);
            for (uint256 i = 0; i < proofLength; i += 2) {
                inputHashes[i / 2] =
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                _hash(proof.scopes[i]),
                                _hash(proof.scopes[i + 1]),
                                _hash(proof.messages[i]),
                                _hash(proof.messages[i + 1]),
                                proof.merkleTreeRoots[i],
                                proof.merkleTreeRoots[i + 1],
                                proof.nullifiers[i],
                                proof.nullifiers[i + 1]
                            )
                        )
                    ) %
                    MODULUS;
            }
        } else {
            // if number of proofs is odd, duplicate the last proof
            inputHashes = new uint256[]((proofLength + 1) / 2);
            for (uint256 i = 0; i < proofLength - 1; i += 2) {
                inputHashes[i / 2] =
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                _hash(proof.scopes[i]),
                                _hash(proof.scopes[i + 1]),
                                _hash(proof.messages[i]),
                                _hash(proof.messages[i + 1]),
                                proof.merkleTreeRoots[i],
                                proof.merkleTreeRoots[i + 1],
                                proof.nullifiers[i],
                                proof.nullifiers[i + 1]
                            )
                        )
                    ) %
                    MODULUS;
            }
            // last proof
            inputHashes[inputHashes.length - 1] =
                uint256(
                    keccak256(
                        abi.encodePacked(
                            _hash(proof.scopes[proofLength - 1]),
                            _hash(proof.scopes[proofLength - 1]),
                            _hash(proof.messages[proofLength - 1]),
                            _hash(proof.messages[proofLength - 1]),
                            proof.merkleTreeRoots[proofLength - 1],
                            proof.merkleTreeRoots[proofLength - 1],
                            proof.nullifiers[proofLength - 1],
                            proof.nullifiers[proofLength - 1]
                        )
                    )
                ) %
                MODULUS;
        }

        // continue hashing pairwise to get the final hash
        // the hashing strategy is the same as the batching strategy in noir-proof-batch/src/batch.ts
        uint256 hashLength = inputHashes.length;
        while (hashLength > 1) {
            // position to store the value for next level
            // reusing inputHashes[] to save memory
            uint256 inputHashesPos = 0;
            for (uint256 i = 0; i < hashLength; i += 2) {
                if (i + 1 != hashLength) {
                    inputHashes[inputHashesPos] =
                        uint256(keccak256(abi.encodePacked(inputHashes[i], inputHashes[i + 1]))) %
                        MODULUS;
                } else {
                    // if a single leaf is left, push it to the next level
                    inputHashes[inputHashesPos] = inputHashes[i];
                }

                ++inputHashesPos;
            }
            // length for the next level
            if (hashLength % 2 == 1) {
                hashLength = hashLength / 2;
                ++hashLength;
            } else {
                hashLength = hashLength / 2;
            }
        }

        uint256 finalHash = inputHashes[0];
        // check finialHash equal to the hash in publicInput
        if (uint256(proof.publicInputs[0]) != finalHash) {
            return false;
        }

        return verifier.verify(proof.proofBytes, proof.publicInputs, 0, true);
    }

    /// @dev Creates a keccak256 hash of a message compatible with the SNARK scalar modulus.
    /// @param message: Message to be hashed.
    /// @return Message digest.
    function _hash(uint256 message) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(message))) >> 8;
    }
}
