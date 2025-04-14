// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

// Library for retrieving verification keys for UltraHonk
library HonkVerificationKey {
    // returning verification keys of the respecting merkle tree depth
    function loadVerificationKey(uint256 merkleTreeDepth, address vkLib) external returns (VerificationKey memory) {
        //TODO - refactor, prevent using delegatecall
        (bool success, bytes memory _vkPointsBytes) = vkLib.delegatecall(
            abi.encodeWithSignature("getPts(uint256)", merkleTreeDepth)
        );
        uint256[42] memory _vkPoints;
        if (success) {
            _vkPoints = abi.decode(_vkPointsBytes, (uint256[42]));
        }
        (uint256 n, uint256 logN) = getNAndLogN(merkleTreeDepth);
        VerificationKey memory vk = VerificationKey({
            circuitSize: uint256(n),
            logCircuitSize: uint256(logN),
            publicInputsSize: uint256(4),
            ql: G1Point({x: uint256(_vkPoints[0]), y: uint256(_vkPoints[1])}),
            qr: G1Point({x: uint256(_vkPoints[2]), y: uint256(_vkPoints[3])}),
            qo: G1Point({x: uint256(_vkPoints[4]), y: uint256(_vkPoints[5])}),
            q4: G1Point({x: uint256(_vkPoints[6]), y: uint256(_vkPoints[7])}),
            qm: G1Point({x: uint256(_vkPoints[8]), y: uint256(_vkPoints[9])}),
            qc: G1Point({x: uint256(_vkPoints[10]), y: uint256(_vkPoints[11])}),
            qArith: G1Point({x: uint256(_vkPoints[12]), y: uint256(_vkPoints[13])}),
            qDeltaRange: G1Point({x: uint256(_vkPoints[14]), y: uint256(_vkPoints[15])}),
            qElliptic: G1Point({x: uint256(_vkPoints[16]), y: uint256(_vkPoints[17])}),
            qAux: G1Point({x: uint256(_vkPoints[18]), y: uint256(_vkPoints[19])}),
            qLookup: G1Point({
                x: 0x304b1f3f6dbf38013e2451e1d3441b59536d30f6f10b2e3d2536666ce5283221,
                y: 0x276cd8fc9a873e4e071bcba6aff6d9ee4b9bacd691a89401857d9015136a7ef8
            }),
            qPoseidon2External: G1Point({x: uint256(_vkPoints[20]), y: uint256(_vkPoints[21])}),
            qPoseidon2Internal: G1Point({x: uint256(_vkPoints[22]), y: uint256(_vkPoints[23])}),
            s1: G1Point({x: uint256(_vkPoints[24]), y: uint256(_vkPoints[25])}),
            s2: G1Point({x: uint256(_vkPoints[26]), y: uint256(_vkPoints[27])}),
            s3: G1Point({x: uint256(_vkPoints[28]), y: uint256(_vkPoints[29])}),
            s4: G1Point({x: uint256(_vkPoints[30]), y: uint256(_vkPoints[31])}),
            t1: G1Point({
                x: 0x2cdb329f4ac54a9b2a6bb49f35b27881fa6a6bb06a51e41a3addbc63b92a09f2,
                y: 0x09de6f6dce6674dfe0bb9a2d33543b23fa70fdaae3e508356ea287353ff56377
            }),
            t2: G1Point({
                x: 0x011733a47342be1b62b23b74d39fb6a27677b44284035c618a4cfa6c35918367,
                y: 0x1b6124ff294c0bbe277c398d606ca94bf37bad466915d4b7b1fcfd2ff798705d
            }),
            t3: G1Point({
                x: 0x233834e0140e5ef7e22c8e9c71b60d1f9ad15ec60b1160db943c043c64e5635b,
                y: 0x2a1e72915741ffdc0d9537378ca015e8943fd1ce6bb8eeb999eb04d9c51b1f4e
            }),
            t4: G1Point({
                x: 0x2ae1cb509ce1e6f5a706388238a045046c7d1b3a1c534d8d1cd1165deb1b3a33,
                y: 0x1f0a2bdf6edefdfa216746a70719395d6c1f362f7bacfdb326d34457994ca6c1
            }),
            id1: G1Point({x: uint256(_vkPoints[32]), y: uint256(_vkPoints[33])}),
            id2: G1Point({x: uint256(_vkPoints[34]), y: uint256(_vkPoints[35])}),
            id3: G1Point({x: uint256(_vkPoints[36]), y: uint256(_vkPoints[37])}),
            id4: G1Point({x: uint256(_vkPoints[38]), y: uint256(_vkPoints[39])}),
            lagrangeFirst: G1Point({
                x: 0x0000000000000000000000000000000000000000000000000000000000000001,
                y: 0x0000000000000000000000000000000000000000000000000000000000000002
            }),
            lagrangeLast: G1Point({x: uint256(_vkPoints[40]), y: uint256(_vkPoints[41])})
        });
        return vk;
    }

    // returning circuit size N and logN based on merkle tree depth
    function getNAndLogN(uint256 merkleTreeDepth) internal pure returns (uint256, uint256) {
        if (merkleTreeDepth < 2) {
            return (8192, 13);
        }
        if (merkleTreeDepth < 11) {
            return (16384, 14);
        }
        if (merkleTreeDepth < 28) {
            return (32768, 15);
        }
        return (65536, 16);
    }

    //TODO - duplicate struct, refactor
    struct VerificationKey {
        // Misc Params
        uint256 circuitSize;
        uint256 logCircuitSize;
        uint256 publicInputsSize;
        // Selectors
        G1Point qm;
        G1Point qc;
        G1Point ql;
        G1Point qr;
        G1Point qo;
        G1Point q4;
        G1Point qLookup; // Lookup
        G1Point qArith; // Arithmetic widget
        G1Point qDeltaRange; // Delta Range sort
        G1Point qAux; // Auxillary
        G1Point qElliptic; // Auxillary
        G1Point qPoseidon2External;
        G1Point qPoseidon2Internal;
        // Copy cnstraints
        G1Point s1;
        G1Point s2;
        G1Point s3;
        G1Point s4;
        // Copy identity
        G1Point id1;
        G1Point id2;
        G1Point id3;
        G1Point id4;
        // Precomputed lookup table
        G1Point t1;
        G1Point t2;
        G1Point t3;
        G1Point t4;
        // Fixed first and last
        G1Point lagrangeFirst;
        G1Point lagrangeLast;
    }

    //TODO - duplicate struct, refactor
    struct G1Point {
        uint256 x;
        uint256 y;
    }
}
