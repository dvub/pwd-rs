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

/*
you can use impl AsRef<[u8]> as the type for the master password/data, which would allow the user to pass a str or other types that can generate a ref to a byte slice
encrypt_if_some should probably be done at the call site instead, if the provided data is Some, call derive_and_encrypt, and if it's not, just don't call the encrypt function
hex encoding should probably happen outside the encrypt function
RustCrypto has in-place functions which can modify the data buffer in-place rather than making a new allocation each encryption (which could help with performance if you're trying to encrypt large blobs of data at a time): https://docs.rs/aes-gcm/latest/aes_gcm/trait.AeadInPlace.html#method.encrypt_in_place
encryption failures probably should be propagated instead of unwrapped, especially since decrypting with the wrong key will result in an error and that should probably be a user-friendly message instead of a stack trace
*/


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
    data: Option<String>,
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
        // an online aes encryption tool could be used to obtain results for comparison,
        // however simply using the decrypt() function is also acceptable
        let plaintext = cipher.decrypt(&nonce, res.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
    }
    #[test]
    fn sha512() {
        // the string literal came from an online hasher to compare results to
        let res = &super::hash(b"test")[..];
        let expected =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert_eq!(res, expected);
    }
    #[test]
    fn kdf() {
        // generate key
        let key = super::generate_key(b"super_secret", b"notrandomsalt");
        // the string literal was obtained from an online pbkdf generator 
        let expected =
            hex_literal::hex!("e9d4ea6e14c8958ec074b355cebe0d78b0f8d45b835bacf213030f9e791e3bbc");
        assert_eq!(key, expected);
    }
    #[test]
    fn derive_and_encrypt() {

        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm, Key,
        };
        // define fields, this is only here so that i *know* i didnt make any spelling mistakes
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let message = b"plaintext message";
        let master_password = b"mymasterpassword";
        let salt = b"salt";
        // get result from derive and encrypt function and decode the resulting string
        let res = super::derive_and_encrypt(master_password, message, nonce, salt);
        let decoded = hex::decode(res).expect("Error decoding result");
        // use the functions from aes-gcm crate to get results and test against
        let key = super::generate_key(master_password, salt);
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher.decrypt(&nonce, decoded.as_ref()).unwrap();
        // obviously, just check for equality here
        assert_eq!(&plaintext, message);
    }
    #[test]
    fn encrypt_if_some() {
    
        use aes_gcm::{Aes256Gcm, aead::{OsRng, AeadCore}};
        let result = super::encrypt_if_some(Some("hello"), "mymasterpassword", Aes256Gcm::generate_nonce(&mut OsRng), "somesalt");  
        assert_eq!(result.unwrap(), Some(_));
    
    }
}
