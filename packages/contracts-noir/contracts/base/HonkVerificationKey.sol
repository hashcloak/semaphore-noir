// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import "./SemaphoreNoirVerifierKeyPts1.sol";
import "./SemaphoreNoirVerifierKeyPts2.sol";

struct G1Point {
    uint256 x;
    uint256 y;
}

struct G1ProofPoint {
    uint256 x_0;
    uint256 x_1;
    uint256 y_0;
    uint256 y_1;
}

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

// Library for retrieving verification keys for UltraHonk
library HonkVerificationKey {
    // returning verification keys of the respecting merkle tree depth
    function loadVerificationKey(uint256 merkleTreeDepth) external pure returns (VerificationKey memory) {
        uint256[42] memory _vkPoints;
        if (merkleTreeDepth < 17) {
            _vkPoints = SemaphoreVerifierKeyPts1.getPts(merkleTreeDepth);
        } else {
            _vkPoints = SemaphoreVerifierKeyPts2.getPts(merkleTreeDepth);
        }

        (uint256 n, uint256 logN) = getNAndLogN(merkleTreeDepth);
        VerificationKey memory vk = VerificationKey({
            circuitSize: uint256(n),
            logCircuitSize: uint256(logN),
            publicInputsSize: uint256(4),
            qr: G1Point({x: uint256(_vkPoints[2]), y: uint256(_vkPoints[3])}),
            ql: G1Point({x: uint256(_vkPoints[0]), y: uint256(_vkPoints[1])}),
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

    function loadBatchingKey() external pure returns (VerificationKey memory) {
        VerificationKey memory vk = VerificationKey({
            circuitSize: uint256(2097152),
            logCircuitSize: uint256(21),
            publicInputsSize: uint256(16),
            ql: G1Point({
                x: uint256(0x224dffa2aaeaedc6b6149fa7a4cb2d2db4b48aa7aebcf12a4eff376ca91907e7),
                y: uint256(0x04cb894b27e063af560b46c25aa713da6e92ce2205843e532b31c3346d748b33)
            }),
            qr: G1Point({
                x: uint256(0x0a9a3d8a12af2e2b80e73f7b4fb1a2b76ac3dd8f68ad0138d95e5bd666877d0c),
                y: uint256(0x1065db107324d016164ccdd9a9372841493046ff7a4d6d8fcbf8208e4eb2233a)
            }),
            qo: G1Point({
                x: uint256(0x1b247d3663a44c03704ea7e08f608e46bf3ee4402294368f6b5336044336ddf3),
                y: uint256(0x0935ba6c9da3223fa5cb39217ce0650ca97c4255791a0c1dad0ff4eba3440bb3)
            }),
            q4: G1Point({
                x: uint256(0x0b542cc196cc8b0eb8b86042ea807fafcd68c0b0e3097570bd9ab388244628b5),
                y: uint256(0x0fd19ff666baf07b4e749b472f7b7517f1f77ab3edcf7902cb5260f5dfe22952)
            }),
            qm: G1Point({
                x: uint256(0x05db220d982083e5d8fbb5964ab426853793114cc97784c0662f7fb49093b15a),
                y: uint256(0x25c91f18c4d5a4e1b44eac89a8373a41efd0de6aff4ff3c7895cb7101c7a31a1)
            }),
            qc: G1Point({
                x: uint256(0x212e0cf40c1e663429ad834887b6bc6cdcb45f8e2fc34ad9a8dbb2c2088acca4),
                y: uint256(0x15baba9110cd7bf6157e312b20343721a19734b786b054f8b7798fe84075052e)
            }),
            qArith: G1Point({
                x: uint256(0x212f1f6c8a813551f1e52ec48c11ec3f3b0fca9997b0581d08bea04ddc0752e0),
                y: uint256(0x0f637990bdbd5adbd912afd325ab847b6fbb3d28ff034c91c1e68a7eac726185)
            }),
            qDeltaRange: G1Point({
                x: uint256(0x2dd763eabd10d073f4b249f0ac9f69796ee4dcfaac96d5a23126decc7912a0d0),
                y: uint256(0x24f49b460ae83eee1d323044f1ca9ffc4c964e1df2e7329b832525e379351d8a)
            }),
            qElliptic: G1Point({
                x: uint256(0x28054cb80059e066f2f4efa92071cd0f2f33f7d03d31143e9565c827c5586ca8),
                y: uint256(0x10e11931417ce0a6612890b8ee982beebf6061224abe73ddcf1207efe2ce49e1)
            }),
            qAux: G1Point({
                x: uint256(0x2d23ee42c21be324ec226f9c7a84fdd0ac32ebd9a08132a26175aa89a8f7e639),
                y: uint256(0x2db48d08acdceae4beb0df6ffac301c84f9e50b6b3b146333bffbbdd880cf7b6)
            }),
            qLookup: G1Point({
                x: uint256(0x17c6d9d50e48678a2ac344538de4c7ece661d9ddf8d6ce71e63ee377b120f70f),
                y: uint256(0x19c51b736e4c5a7d8380246160d19aad54bcdd8f21bebc775e9dfb36b9a73d45)
            }),
            qPoseidon2External: G1Point({
                x: uint256(0x137a790e4e5fc4e6e3e2c2915904989f85538bd81adcf3a21d179c351cd34ccc),
                y: uint256(0x0a6b574aa29f7771b627bd5a5c2b78925336e705dd8a85153954b7f7992a8a0c)
            }),
            qPoseidon2Internal: G1Point({
                x: uint256(0x286835edb3d8659f60690e4b4b44c4fa3e2c735c34d138fe59cbbf7836431d97),
                y: uint256(0x1525b6fba23e02e5e78e1f41b028aeada5a7ad87f2e52ff76a305a2bf0790a70)
            }),
            s1: G1Point({
                x: uint256(0x010843239d7b7a2e9c66625f2913feb13e818265bad80a923ca0eaf38161467f),
                y: uint256(0x141ce316b7ca52edd89b46aae19ffefe70ed9011f8bc88590eaa4f5158a4ee57)
            }),
            s2: G1Point({
                x: uint256(0x21723f776efeb964ff91ac76e63c4b79b8a22dd373d4848de905c1dd528320ba),
                y: uint256(0x1930025d49aa27db7b52aad16d9c307d3ec2c8ab38ce9e53252c9bf3c6266305)
            }),
            s3: G1Point({
                x: uint256(0x0248ab05faae9973fa1717292832ad458657ae33a7da34c092c3837ebd0014d0),
                y: uint256(0x2e3b09e1da086a912a286a4c6a4dff1c43e9a2129968d95fb701d316fc1e7767)
            }),
            s4: G1Point({
                x: uint256(0x2acb44e717fff904dc65845d6571bb9d03ae2f9e8f5741b54398002d36f628be),
                y: uint256(0x17914e40c463428fa4e860bdf2be5a36d9aac2a8abda95dc86934cbdae4edf77)
            }),
            t1: G1Point({
                x: uint256(0x1f1156b93b4396e0dac3bd312fdc94243cf3e0cfba606d27d5999f4927ff92b3),
                y: uint256(0x116a7935196d39ea9178a285c53a6b419d9961d76a65ed28914ca5cc3ffd2433)
            }),
            t2: G1Point({
                x: uint256(0x23aebc5efc1d0e6d03030b242308fdf369409c76a0245d4f389193b554c30065),
                y: uint256(0x19f38f8e7cf18f375d75db06fca92a0cbfc1214af084c189478e34dc04c77419)
            }),
            t3: G1Point({
                x: uint256(0x15642d62fc17d119ba4afb77ab424e0a771b5bbb501c75790a1a4e2906931045),
                y: uint256(0x21cea98314ec6efc5f8f1f648f42a7a5c1396036397af54a729801cc1c37d4e2)
            }),
            t4: G1Point({
                x: uint256(0x1f3bd0ebf0709ac30745d0dafb183cdd5b4a42e59fe1e447cad24659049d13a7),
                y: uint256(0x05900180ddd1cec6e340c70c9bff6f16c2efd51d298fee5fce4355fc26890195)
            }),
            id1: G1Point({
                x: uint256(0x111337dbd2c760ab3c16b736c3e0963fcab131869553ab7269019a852a6e19d5),
                y: uint256(0x0d8f188d46d4662c6e450723693dabd05cf70547518af7295c0b1665734363c6)
            }),
            id2: G1Point({
                x: uint256(0x109474fbac03e39a12123247d537b5b2f67a8ab2d56c649c23ead379cae6701a),
                y: uint256(0x03bb08f5ad597bcc784d8866cebfda656225dbea2977aeaaf8a580fbe3535f83)
            }),
            id3: G1Point({
                x: uint256(0x09bb85ad242bfd649cede6fd276c495c71ae752a6849552b1cfa147243cf4bb3),
                y: uint256(0x063a3fef5f97c2b4291837fb473d6ed4f0f8d94462a97dd586a70b32aa12bc51)
            }),
            id4: G1Point({
                x: uint256(0x2ab7067253088d36c661bd99c9bd367b53f89c7f953bcc775e2bc18209dc9679),
                y: uint256(0x06f57a8492c43a8ab8d61b828e00010fe074d48f6c99836c769fe43d8ac16fd6)
            }),
            lagrangeFirst: G1Point({
                x: uint256(0x0000000000000000000000000000000000000000000000000000000000000001),
                y: uint256(0x0000000000000000000000000000000000000000000000000000000000000002)
            }),
            lagrangeLast: G1Point({
                x: uint256(0x007280c5169a0e1f859a500138817ec4b6fb9150ed11685a09038ea35070642d),
                y: uint256(0x16658259e029bb766fe0d828342f9ef7151c97526c14e4531a6b1778adccedf5)
            })
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

    function checkInvariant(uint8 maxDepth) external pure {
        SemaphoreVerifierKeyPts1.checkInvariant(maxDepth);
        SemaphoreVerifierKeyPts2.checkInvariant(maxDepth);
    }
}
