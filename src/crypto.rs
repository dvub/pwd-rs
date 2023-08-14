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

// hash a given &str using Sha512
// returns a String
pub fn hash(
    text: &[u8],
) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
    let mut hasher = Sha256::new();
    hasher.update(text);
    hasher.finalize()
}

// generate a 32-byte long key from the master password and a salt
pub fn generate_key(master_password: &[u8], salt: &[u8]) -> [u8; 32] {
    // number of iterations
    let n = 4096;
    // Expected value of generated key:
    let mut key1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password, salt, n, &mut key1);
    key1
}

// encrypt a plaintext password with AES-256-GCM given a key (derived from the above function) and a nonce
pub fn encrypt(
    plaintext: &[u8],
    derived_key: [u8; 32],
    nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(&key);
    cipher.encrypt(&nonce, plaintext.as_ref()).unwrap()
}

pub fn decrypt(
    ciphertext: &[u8],
    derived_key: [u8; 32],
    nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(&key);
    cipher.decrypt(&nonce, ciphertext.as_ref())
        .expect("error decrypting data")
}


pub fn derive_and_encrypt(
    master_password: &[u8],
    data: &[u8],
    aes_nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: &[u8],
)-> String {
    let derived_key = generate_key(master_password, kdf_salt);
    let encrypted = encrypt(data, derived_key, aes_nonce);
    hex::encode(encrypted)
}

pub fn encrypt_if_some(
    data: Option<&str>,
    master_password: &str,
    aes_nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: &str
) -> Option<String> {
    match data {
        Some(val) => {
            Some(derive_and_encrypt(master_password.as_bytes(), val.as_bytes(), aes_nonce, kdf_salt.as_bytes()))
        }
        None => {
            None
        }
    }
}

pub fn derive_and_decrypt(
    master_password: &[u8],
    data: &[u8],
    aes_nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: &[u8],
)-> String {
    let derived_key = generate_key(master_password, kdf_salt);
    let decrypted = decrypt(data, derived_key, aes_nonce);
    let decoded = hex::decode(decrypted).expect("error decoding decrypted data");
    
    String::from_utf8(decoded).unwrap()
}

pub fn decrypt_if_some(
    data: Option<&str>,
    master_password: &str,
    aes_nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: &str
) -> Option<String> {
    match data {
        Some(val) => {
            Some(derive_and_decrypt(master_password.as_bytes(), val.as_bytes(), aes_nonce, kdf_salt.as_bytes()))
        }
        None => {
            None
        }
    }
}


 
#[cfg(test)]
mod tests {

    #[test]
    fn aes() {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm, Key,
        };

        let plain_key = b"this is the key. 32 bytes long!!";

        let key = Key::<Aes256Gcm>::from_slice(plain_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(key);

        let res = super::encrypt(b"plaintext message", *plain_key, nonce);

        let plaintext = cipher.decrypt(&nonce, res.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
    }
    #[test]
    fn sha512() {
        let res = &super::hash(b"test")[..];
        let expected =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert_eq!(res, expected);
    }
    #[test]
    fn kdf() {
        let key = super::generate_key(b"super_secret", b"notrandomsalt");
        let expected =
            hex_literal::hex!("e9d4ea6e14c8958ec074b355cebe0d78b0f8d45b835bacf213030f9e791e3bbc");
        assert_eq!(key, expected);
    }

}
