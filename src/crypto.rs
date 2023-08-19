use aes_gcm::{
    aead::{
        consts::{B0, B1},
        generic_array::GenericArray,
    },
    aead::{Aead, KeyInit},
    Aes256Gcm, Key,
};
use pbkdf2::pbkdf2_hmac;
use sha2::{
    digest::typenum::{UInt, UTerm},
    Digest, Sha256,
};
// TODO
/*
    encryption failures probably should be propagated instead of unwrapped,
    especially since decrypting with the wrong key will result in an error
    and that should probably be a user-friendly message instead of a stack trace
*/

/// Hashes `text` using `Sha256`.
pub fn hash(
    text: &[u8],
) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
    let mut hasher = Sha256::new();
    hasher.update(text);
    hasher.finalize()
}


/// Derives a key from the provided `master_password`, and encrypts if `data` is `Some`; Otherwise, returns `None`.
pub fn encrypt(
    master_password: impl AsRef<[u8]>,
    data: Option<impl AsRef<[u8]>>,
    aes_nonce: &GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: impl AsRef<[u8]>,
) -> Option<String> {
    match data {
        Some(value) => {
            // number of iterations
            let n = 4096;
            // Expected value of generated key:
            let mut derived_key = [0u8; 32];
            pbkdf2_hmac::<Sha256>(
                master_password.as_ref(),
                kdf_salt.as_ref(),
                n,
                &mut derived_key,
            );

            let key = Key::<Aes256Gcm>::from_slice(&derived_key);
            let cipher = Aes256Gcm::new(&key);

            let encrypted = cipher.encrypt(&aes_nonce, value.as_ref()).unwrap();
            let encoded = hex::encode(&encrypted);
            Some(encoded)
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn sha512() {
        // the string literal came from an online hasher to compare results to
        let res = &super::hash(b"test")[..];
        let expected =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert_eq!(res, expected);
    }
    #[test]
    fn encrypt() {
        use aes_gcm::{aead::OsRng, AeadCore, Aes256Gcm, Key, KeyInit, aead::Aead};

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let res = super::encrypt(
            "mymasterpassword",
            Some("data"),
            &nonce,
            "salt",
        );
        // sourced from: https://neurotechnics.com/tools/pbkdf2-test
        // hex::decode() will decode into an array and then create an encryption key for us to compare to
        let expected = hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c").unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&expected);

        let cipher = Aes256Gcm::new(&key);
        let ciphertext = cipher.encrypt(&nonce, b"data".as_ref()).unwrap();
        assert_eq!(res.unwrap(), hex::encode(ciphertext));
    }
}
