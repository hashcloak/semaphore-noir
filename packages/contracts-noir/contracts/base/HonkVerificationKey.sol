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
            publicInputsSize: uint256(17),
            ql: G1Point({
                x: uint256(0x00af76b029a085396de14df021bcbef569912920b597986dab15bdfef70cd8fa),
                y: uint256(0x1efe0d41f24dc916c7ced45e9e8024c4bdd45dd2af3205713ba9e340dc432db1)
            }),
            qr: G1Point({
                x: uint256(0x2e70c3990bf4d1ef95023e56c6ba102c131578c45d9f35ee2a9c2dbd0ca284f6),
                y: uint256(0x1e64cc6f32994852e5e87ec14e161d97249e4341a579a76127f2f85bd9fb22a3)
            }),
            qo: G1Point({
                x: uint256(0x2cfe5b7785d0df03a8330cd53f7b7da00c20ee6721f6c4c0cb0ffd0ba8cfbaae),
                y: uint256(0x26c4b1a9e7399b92a4afd2b800868ae982f77f008c4a46094186a9c12d0b9ba4)
            }),
            q4: G1Point({
                x: uint256(0x13d2aa6ec85b172fadcca3af8d403b895869b0440ac242899def40326dde197d),
                y: uint256(0x253e1594dc07e2f1a3cba9a7f6b8312f6866ec217b14e2b80ddee32ff2372002)
            }),
            qm: G1Point({
                x: uint256(0x1aa9020d2ffe48a5d4e61eb2676b73f656dcb73647b9685d62522e93e92cf7eb),
                y: uint256(0x11157ba99d695274ff68e9008255e4ecd1d7f78f900de62798762645b5593780)
            }),
            qc: G1Point({
                x: uint256(0x0e65b70038ce6dcf8f91d8e781ebed549df2c7dcdef37266c0330166ec763f4e),
                y: uint256(0x24bc4ec179519918bab93327b04a9712c190c65903d646769491888722c6fd0d)
            }),
            qArith: G1Point({
                x: uint256(0x21362987ae91a50fd2b484ed201bf75d460dbaaeb77cca4afcb75f81085991ee),
                y: uint256(0x023bfd169e77fc8a1341c625680a43369aa842f001c2e0b14d3914d70b7da616)
            }),
            qDeltaRange: G1Point({
                x: uint256(0x29a99131347c75cb45935d2df3f2e2c0dd89424f3065e0fb258502d7c3149b06),
                y: uint256(0x092e06a755aa7f97edd93ca95d1f0c23edd963e64cbc870879d7f8a3f0a2a53b)
            }),
            qElliptic: G1Point({
                x: uint256(0x13d6a0b8a69b0704140760713ef6f234eca6b9f46f7c96e41d99eb2afe059337),
                y: uint256(0x15a4902cbb12c558ca24f2c4e04e5d9498bd7c36a35d8c295b0755469a2176fb)
            }),
            qAux: G1Point({
                x: uint256(0x1c866d694a291726bbdd01457d2ccb388eb6d0b85a467b16cc4da9f6fb48cd6e),
                y: uint256(0x280302b4de7028562030662083fc621519d0bdca8e99f793b618e9950c888358)
            }),
            qLookup: G1Point({
                x: uint256(0x278ee6c0ec01157d9efabd02fd62d1db452512ad93067821d8e4b1ce0c2e6f23),
                y: uint256(0x1e030c621c04be8d3d7c27e86bf3833635601d032ed26f7227aa5a2100b53e4b)
            }),
            qPoseidon2External: G1Point({
                x: uint256(0x0a150da86013d37b90e7de36496f44946d660bad976163ac7992ec7230d6ee3f),
                y: uint256(0x1593f7e8ef9111dc93b91f19022b6d26833c6b7b0fc21ab34001daf68069419c)
            }),
            qPoseidon2Internal: G1Point({
                x: uint256(0x1ff7fd70f4c2fb5d17d59ccc80aceee4f869e089f1ff403d2932e6c9f72b201c),
                y: uint256(0x2f20fca8be2502ddfa648ef137b5a4f99ee822e13f6d92ea76512befcba4cb36)
            }),
            s1: G1Point({
                x: uint256(0x21133e2f7fbf559fcabed807422c8dede079ac66bd5e0a3b6365a36d41d13001),
                y: uint256(0x29625c645c01360da28f8edbdae828424724c586d1843426f49f8a9899bea110)
            }),
            s2: G1Point({
                x: uint256(0x22ae2116f08eee3a15dfa2cc3de5c3912c114b42f7d7a6459d46e940574707f0),
                y: uint256(0x01c2b204d2026e697ae79cbebf9541cf456eec08bbf0941b7a8dad10c3948ecb)
            }),
            s3: G1Point({
                x: uint256(0x0aaa5912819926b550505b37f4e0fa3be8ea8360a3a45e8303231f1069f4f524),
                y: uint256(0x28fb656e68f4d14622cefd36cfd57b7713dccb2f2d1f9cd9dd5ff6260c010fb5)
            }),
            s4: G1Point({
                x: uint256(0x199b36bd23bda2b389049319fd80d01430111697ff777a045182da5a783b52be),
                y: uint256(0x058ea6af2bae2b2ad05974a50b0826006960110374616f4aa0257a64626b91ee)
            }),
            t1: G1Point({
                x: uint256(0x06ad602dbefb48e4fd97ad3e6b26cfe9b586c7a328d999429ed5121cb66a044e),
                y: uint256(0x2d6e23f9c535c3c78030ca87620c5b7ed19e80fc500fa06e2ee82b3da63999df)
            }),
            t2: G1Point({
                x: uint256(0x2c71e0ca8ce932bbc1bc27cc01d3bf4666d9a925170fb5b12c7b23808b161479),
                y: uint256(0x113db4e7a30a943282c2a1e8a5e63b08c9b837b26d4bbadd003509ba019b8d8c)
            }),
            t3: G1Point({
                x: uint256(0x16f4fd08e3c1b1ef24a475831dac8b9be77690fe4bbf969411f04554b5297097),
                y: uint256(0x10e66bf72fd0b9a0c436caf8306d03e872959e21a0af5377cfc9ae7266c8b1be)
            }),
            t4: G1Point({
                x: uint256(0x1f493f573098c071d2f5b58db4e8b93fe7768092818a06cdf46f2c6ce09fe79e),
                y: uint256(0x15796263418edb897ecd6891ca61c3f1711f000d503c918911d343911d04d32c)
            }),
            id1: G1Point({
                x: uint256(0x0f14040ac3a31a4ab1a209d059d91b772db7f2e0f46f3a31f630cdacdf29fe6a),
                y: uint256(0x0ec65e9f07d9e5066b5a14ce9259cc2039e7f0e5c7acea108f181b9c60c137d7)
            }),
            id2: G1Point({
                x: uint256(0x22713f12fac4974e9372d96b0df6c4d6064d1e4c5657f2c9178c538b5b6fcac0),
                y: uint256(0x0c0e2b246768e44607e732b8f69ce6e16d463cabdf9006152137f365a9c0bef5)
            }),
            id3: G1Point({
                x: uint256(0x172006483fadd4bba36a75950ec726b4109059dd670060a88fbf3ea619a865f6),
                y: uint256(0x2b2ae015863d122ac04b0947f6f565d300851943f1b2db78e9812135b9c65e27)
            }),
            id4: G1Point({
                x: uint256(0x08dd4bc155e6e8c6b0caf22631aad4198aadd3c70cbdc20f9ea42456047cd12e),
                y: uint256(0x0d20e193ba18173d9b939fe59cf669c801731d432e0f32e8ffa05116b7729e60)
            }),
            lagrangeFirst: G1Point({
                x: uint256(0x0000000000000000000000000000000000000000000000000000000000000001),
                y: uint256(0x0000000000000000000000000000000000000000000000000000000000000002)
            }),
            lagrangeLast: G1Point({
                x: uint256(0x25fc4c7bf131eb404f5cb90c57933b4d2c76d44b6f49e3638103874d37300a0e),
                y: uint256(0x2a25fce58d87d78ee12d91bdb3fb7fd30cbb1e83c2e804d09f19ad4cca8c14e9)
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
