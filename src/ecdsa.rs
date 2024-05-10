use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use std::time::Instant;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

pub fn sign_message(signing_key: &SigningKey, message: &str) -> Vec<u8> {
    let signature: k256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let der_signature = signature.to_der();
    der_signature.as_bytes().to_vec()
}


pub fn sign_u8_type(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: k256::ecdsa::Signature = signing_key.sign(message);
    let der_signature = signature.to_der();
    der_signature.as_bytes().to_vec()
}

pub fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    if let Ok(signature) = k256::ecdsa::Signature::from_der(signature) {
        return verifying_key.verify(message, &signature).is_ok()
    } 
    false
}

// fn sig_test() {
//     let (signing_key, verifying_key) = generate_keypair();
//     let message = "Hello, world!";
//     let start = Instant::now();
//     let signature = sign_message(&signing_key, message);
//     let is_valid = verify_signature(&verifying_key, message, &signature);
//     println!("Is signature valid? {}", is_valid);
//     println!("The whole sig/verify time: {:?}", start.elapsed());
// }

// #[cfg(test)]
// mod tests {
//     use crate::ecdsa::sig_test;

//     #[test]
//     fn test_sig() {
//         sig_test();
//     }
// }