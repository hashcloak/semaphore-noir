use ec::bjj::BabyJubJubParams;
use ec::Curve;
use ec::scalar_field::ScalarField;
use std::field::bn254::assert_lt;
use std::hash::poseidon::bn254::hash_2 as poseidon;
use trees::{merkle::MerkleTree, types::MembershipProver};

// TODO: how to adjust this?
comptime global DEPTH: u32 = 1;

// ref: https://github.com/noir-lang/noir-edwards/blob/main/src/test.nr#L6C8-L6C13
global BASE8: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

// 251 bit value
global L: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

fn main(
    secretKey: Field,
    indexes: Field, // a single field representing the index-bits for the merkle proof
    hashPath: [Field; DEPTH],
    merkleTreeRoot: pub Field,
    scope: pub Field, // hashed
    message: pub Field, // hashed
) -> pub Field {
    // Ensure secret_key < l
    assert_lt(secretKey, L);

    let generator: Curve<BabyJubJubParams> = Curve { x: BASE8[0], y: BASE8[1] };
    let secretScalar: ScalarField<63> = ScalarField::from(secretKey);
    let pubkey = generator.mul(secretScalar);

    let identityCommitment = poseidon([pubkey.x, pubkey.y]);

    let mt = MerkleTree { root: merkleTreeRoot, hasher: poseidon };
    // Verifies membership
    mt.membership(identityCommitment, indexes, hashPath);

    // Nullifier = hash(scope, secret_key)
    let nullifier = poseidon([scope, secretKey]);

    nullifier
}

// For testing purposes
// Adaption from https://github.com/noir-lang/noir/blob/dc0f1c2b84248f2ced41e6115ee8e25c0fa78dfc/noir_stdlib/src/field/mod.nr#L265C5-L274C6
pub fn from_be_bits<let N: u32>(bytes: [u1; N]) -> Field {
    let mut v = 1;
    let mut result = 0;

    for i in 0..N {
        result += (bytes[N - 1 - i] as Field) * v;
        v = v * 2;
    }
    result
}

// Values from "Should generate a Semaphore proof" test from proof package
#[test]
fn test_main() {
    let secretKey = 1072931509665125050858164614503996272893941281138625620671594663472720926391;

    let mut indexBits: [u1; DEPTH] = [0; DEPTH];
    indexBits[0] = 1;

    let mut hashPath = [0; 1];
    hashPath[0] = 7853200120776062878684798364095072458815029376092732009249414926327459813530;

    let root = 4990292586352433503726012711155167179034286198473030768981544541070532815155;
    let scope = 170164770795872309789133717676167925425155944778337387941930839678899666300;
    let message = 8665846418922331996225934941481656421248110469944536651334918563951783029;

    let nullifier = main(
        secretKey,
        from_be_bits(indexBits),
        hashPath,
        root,
        scope,
        message,
    );

    assert(
        nullifier == 17540473064543782218297133630279824063352907908315494138425986188962403570231,
    );
}
