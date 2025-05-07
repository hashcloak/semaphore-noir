use dep::std::verify_proof;

global N: u32 = 2;

// A proof produced by a previous batch circuit
struct BatchProof {
    verification_key: [Field; 128],
    proof: [Field; 456],
    key_hash: Field, // Apparently this is 0x00 for now, but we still make it dynamic
}

// Batch 2 Batch proofs into a single proof
// Note: the inputs *cannot* be raw Semaphore proofs.
fn main(bp: [BatchProof; N]) {
    // Note that actual verification happens when this proof gets verified
    for i in 0..N {
        verify_proof(bp[i].verification_key, bp[i].proof, [], bp[i].key_hash);
    }
}
