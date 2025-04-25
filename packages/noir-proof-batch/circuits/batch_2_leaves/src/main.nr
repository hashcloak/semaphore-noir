use dep::std::verify_proof;

global N: u32 = 2;

struct SemaphoreProof {
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 4],
    key_hash: Field, // Apparently this is 0x00 for now, but we still make it dynamic
}

// Batch 2 Semaphore proofs into a single proof
fn main(sp: [SemaphoreProof; N]) {
    // Note that actual verification happens when this proof gets verified
    for i in 0..N {
        verify_proof(
            sp[i].verification_key,
            sp[i].proof,
            sp[i].public_inputs,
            sp[i].key_hash,
        );
    }
}
