// blehhhh

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

/// Hashes `text` using `Sha256`.
pub fn hash(
    text: &[u8],
) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
    let mut hasher = Sha256::new();
    hasher.update(text);
    hasher.finalize()
}
// pbkdf2 function
fn derive_key(master_password: impl AsRef<[u8]>, kdf_salt: impl AsRef<[u8]>) -> [u8; 32] {
    // number of iterations
    // correct me if i'm wrong on the following::

    // this is one of the more important pieces of data that a bad actor would need
    // if someone happened to know a user's master password, the next thing to know would be the salt (which is stored in the database)
    // and then the number of iterations, to replicate keys

    // if this was closed source and the code was obfuscated, this wouldn't be exposed information
    let n = 4096;
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.as_ref(),
        kdf_salt.as_ref(),
        n,
        &mut derived_key,
    );
    derived_key
}
// i know this code smells pretty bad, i'm sorry
// this is just really the easiest way i could think of
// without rewriting my ENTIRE codebase for the project

// if i was more experienced with rust i would refactor everything, but i'm not.
// so you get this for now.
// i'll point out the main problems with this
pub fn encrypt(
    master_password: impl AsRef<[u8]>,
    data: Option<impl AsRef<[u8]>>, // this function should not even take in an optional parameter
    aes_nonce: &GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: impl AsRef<[u8]>,
) -> Option<String> {
    //
    let derived_key = derive_key(master_password, kdf_salt);

    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(&key);
    // same thing with not dealing with options
    match data {
        Some(val) => {
            // this error should be propagated
            let encrypted = cipher
                .encrypt(&aes_nonce, val.as_ref())
                .expect("Error encrypting!");
            // encoding should not really take place here
            Some(hex::encode(encrypted))
        }
        None => None,
    }
}
pub fn decrypt(
    master_password: impl AsRef<[u8]>,
    data: Option<impl AsRef<[u8]>>, // this function should not even take in an optional parameter
    aes_nonce: &GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    kdf_salt: impl AsRef<[u8]>,
) -> Option<String> {
    //
    let derived_key = derive_key(master_password, kdf_salt);

    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(&key);
    // same thing with not dealing with options
    match data {
        Some(val) => {

            // this error should be propagated
            // just a note: since we're doing all this decode+encode nonsense
            // decoding has to happen first because that's how the data is read from the database,
            // then once it's been decoded we can decrypt the data
            let decoded = hex::decode(val).expect("error decoding data");
            let decrypted = cipher
                .decrypt(&aes_nonce, decoded.as_ref())
                .expect("Error decrypting!"); // same thing here
            // and same thing here...
            Some(String::from_utf8(decrypted).expect("Error converting.."))
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, aead::OsRng, AeadCore, Aes256Gcm, Key, KeyInit};
    #[test]
    fn sha512() {
        // the string literal came from an online hasher to compare results to
        let res = &super::hash(b"test")[..];
        let expected =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert_eq!(res, expected);
    }
    #[test]
    fn derive_key() {
        let res = super::derive_key("mymasterpassword", "salt");
        let expected =
            hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c")
                .unwrap();
        assert_eq!(res.to_vec(), expected);
    }
    #[test]
    fn encrypt() {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        // function to test
        let res = super::encrypt("mymasterpassword", Some("data"), &nonce, "salt");

        // sourced from: https://neurotechnics.com/tools/pbkdf2-test
        // hex::decode() will decode into an array and then create an encryption key for us to compare to
        let key =
            hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c")
                .unwrap();
        // manually creating this key/cipher
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(&key);

        // encrypt and compare!
        let ciphertext = cipher.encrypt(&nonce, b"data".as_ref()).unwrap();

        assert_eq!(res.unwrap(), hex::encode(ciphertext));
    }
    #[test]
    fn decrypt() {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let key =
            hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c")
                .unwrap();
        // manually creating this key/cipher
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(&key);


        let ciphertext = hex::encode(cipher.encrypt(&nonce, b"data".as_ref()).unwrap());

        // here's the function we're testing
        let result = super::decrypt("mymasterpassword", Some(ciphertext), &nonce, "salt").unwrap();

        assert_eq!(result, "data");
    }
}
