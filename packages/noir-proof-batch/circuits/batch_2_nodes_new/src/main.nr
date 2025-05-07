use dep::std::verify_proof;
use std::hash::poseidon::bn254::hash_2 as poseidon;

// A proof produced by a previous batch circuit
struct BatchProof {
    verification_key: [Field; 128],
    proof: [Field; 456],
    key_hash: Field, // Apparently this is 0x00 for now, but we still make it dynamic
    nullifiers_hash: Field
}

// Batch 2 Batch proofs into a single proof
// Note: the inputs *cannot* be raw Semaphore proofs.
fn main(bp: [BatchProof; 2]) -> pub Field {
    // Note that actual verification happens when this proof gets verified
    verify_proof(bp[0].verification_key, bp[0].proof, [], bp[0].key_hash);
    verify_proof(bp[1].verification_key, bp[1].proof, [], bp[1].key_hash);

    // Hash hashes of nullifiers together
    poseidon([bp[0].nullifiers_hash, bp[1].nullifiers_hash])
}
