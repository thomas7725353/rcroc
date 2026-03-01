use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

use crate::models::PBKDF2_ITERS;

pub fn derive_aes_key(shared_key: &[u8], passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_key);
    hasher.update(passphrase.as_bytes());
    let prehash = hasher.finalize();

    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&prehash, salt, PBKDF2_ITERS, &mut out);
    out
}
