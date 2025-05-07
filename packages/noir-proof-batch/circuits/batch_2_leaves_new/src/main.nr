use dep::std::verify_proof;
use std::hash::poseidon::bn254::hash_2 as poseidon;

struct SemaphoreProof {
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 4],
    key_hash: Field, // Apparently this is 0x00 for now, but we still make it dynamic
}

// Batch 2 Semaphore proofs into a single proof
fn main(sp: [SemaphoreProof; 2]) -> pub Field {
    // Note that actual verification happens when this proof gets verified
    verify_proof(
        sp[0].verification_key,
        sp[0].proof,
        sp[0].public_inputs,
        sp[0].key_hash,
    );

    verify_proof(
        sp[1].verification_key,
        sp[1].proof,
        sp[1].public_inputs,
        sp[1].key_hash,
    );

    // Hash nullifiers together
    poseidon([sp[0].public_inputs[3], sp[1].public_inputs[3]])
}
