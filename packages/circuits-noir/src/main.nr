use ec::bjj::BabyJubJubParams;
use ec::Curve;
use ec::scalar_field::ScalarField;
use std::field::bn254::assert_lt;
use std::hash::poseidon::bn254::hash_2 as poseidon;
use trees::{merkle::MerkleTree, types::MembershipProver};

pub global PROOF_LEN: u32 = 2;

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
    hashPath: [Field; PROOF_LEN],
    merkleTreeRoot: pub Field,
    scope: pub Field,
    message: pub Field,
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

    // Nullifier = hash(scope, secretKey)
    let nullifier = poseidon([scope, secretKey]);

    nullifier
}
