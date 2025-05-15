use dep::std::verify_proof;

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

    // hash nullifiers, roots, scope, message together
    let mut public_input_bytes = [0 as u8; 256];
    for i in 0..32 {
        //proof_1_scope
        public_input_bytes[i] = sp[0].public_inputs[0].to_be_bytes::<32>()[i];
        //proof_2_scope
        public_input_bytes[i + 32] = sp[1].public_inputs[0].to_be_bytes::<32>()[i];
        //proof_1_message
        public_input_bytes[i + 64] = sp[0].public_inputs[1].to_be_bytes::<32>()[i];
        //proof_2_message
        public_input_bytes[i + 96] = sp[1].public_inputs[1].to_be_bytes::<32>()[i];
        //proof_1_root
        public_input_bytes[i + 128] = sp[0].public_inputs[2].to_be_bytes::<32>()[i];
        //proof_2_root
        public_input_bytes[i + 160] = sp[1].public_inputs[2].to_be_bytes::<32>()[i];
        //proof_1_nullifier
        public_input_bytes[i + 192] = sp[0].public_inputs[3].to_be_bytes::<32>()[i];
        //proof_2_nullifier
        public_input_bytes[i + 224] = sp[1].public_inputs[3].to_be_bytes::<32>()[i];
    }

    Field::from_be_bytes(keccak256::keccak256(public_input_bytes, 256))
}

// #[test]
// fn test_hash() {
//     let sp0_public_input: [Field; 4] = [0, 1, 2, 3];
//     let sp1_public_input: [Field; 4] = [4, 5, 6, 7];
//     let mut public_input_bytes = [0 as u8; 256];
//     for i in 0..32 {
//         //proof_0_nullifiers
//         public_input_bytes[i] = sp0_public_input[0].to_be_bytes::<32>()[i];
//         //proof_1_nullifiers
//         public_input_bytes[i + 32] = sp1_public_input[0].to_be_bytes::<32>()[i];
//         //proof_1_roots
//         public_input_bytes[i + 64] = sp0_public_input[1].to_be_bytes::<32>()[i];
//         //proof_2_roots
//         public_input_bytes[i + 96] = sp1_public_input[1].to_be_bytes::<32>()[i];
//         //proof_1_scope
//         public_input_bytes[i + 128] = sp0_public_input[2].to_be_bytes::<32>()[i];
//         //proof_2_scope
//         public_input_bytes[i + 160] = sp1_public_input[2].to_be_bytes::<32>()[i];
//         //proof_1_message
//         public_input_bytes[i + 192] = sp0_public_input[3].to_be_bytes::<32>()[i];
//         //proof_2_message
//         public_input_bytes[i + 224] = sp1_public_input[3].to_be_bytes::<32>()[i];
//     }

//     let result = Field::from_be_bytes(keccak256::keccak256(public_input_bytes, 256));

//     println(result);
// }
