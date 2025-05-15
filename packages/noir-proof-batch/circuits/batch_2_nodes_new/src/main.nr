use dep::std::verify_proof;

// A proof produced by a previous batch circuit
struct BatchProof {
    verification_key: [Field; 128],
    proof: [Field; 456],
    key_hash: Field, // Apparently this is 0x00 for now, but we still make it dynamic
    public_inputs_hash: Field,
}

// Batch 2 Batch proofs into a single proof
// Note: the inputs *cannot* be raw Semaphore proofs.
fn main(bp: [BatchProof; 2]) -> pub Field {
    // Note that actual verification happens when this proof gets verified
    verify_proof(
        bp[0].verification_key,
        bp[0].proof,
        [bp[0].public_inputs_hash],
        bp[0].key_hash,
    );
    verify_proof(
        bp[1].verification_key,
        bp[1].proof,
        [bp[1].public_inputs_hash],
        bp[1].key_hash,
    );

    // Hash hashes of public_inputs together
    let mut public_input_bytes = [0 as u8; 64];
    for i in 0..32 {
        // bp[0].public_inputs_hash
        public_input_bytes[i] = bp[0].public_inputs_hash.to_be_bytes::<32>()[i];
        // bp[1].public_inputs_hash
        public_input_bytes[i + 32] = bp[1].public_inputs_hash.to_be_bytes::<32>()[i];
    }

    Field::from_be_bytes(keccak256::keccak256(public_input_bytes, 64))
}
