mod args;

use args::{Commands, PwdArgs};
use clap::Parser;

pub mod models;
pub mod schema;

fn main() {
    let args = PwdArgs::parse();

    match args.command {
        Commands::Add(add_args) => if add_args.email.is_some() {},
        Commands::Get(_a) => {}
    }
}
/*
// function to generate an encryption key given a password
fn gen_key(password: &[u8]) -> ([u8; 32], [u8; 32], u32){

    use aes_gcm::aead::OsRng;
    use pbkdf2::pbkdf2_hmac;

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let n = 4096;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, n, &mut key);
    (key, salt, n)
}
*/

// these tests are mainly to help me understand how all the crates work tbh
//
#[cfg(test)]
mod tests {
    #[test]
    fn aes() {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm, Key,
        };
        let key_plaintext = b"this is the key. 32 bytes long!!";
        let key = Key::<Aes256Gcm>::from_slice(key_plaintext);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
    }
    #[test]
    fn sha2() {
        use hex_literal::hex;
        use sha2::{Digest, Sha256};
        // create a Sha256 object
        let mut hasher = Sha256::new();

        // write input message
        hasher.update(b"hello world");

        // read hash digest and consume hasher
        let result = hasher.finalize();

        assert_eq!(
            result[..],
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")[..]
        );
    }
    #[test]
    fn pbkdf2() {
        use pbkdf2::pbkdf2_hmac;
        use hex_literal::hex;
        use sha2::Sha256;
        let password = b"password";
        let salt = b"salt";
        // number of iterations
        let n = 600_000;
        // Expected value of generated key
        let expected = hex!("669cfe52482116fda1aa2cbe409b2f56c8e45637");

        let mut key1 = [0u8; 20];
        pbkdf2_hmac::<Sha256>(password, salt, n, &mut key1);
        assert_eq!(key1, expected);
    }

    #[test]
    fn establish_connection() {
        use dotenvy::dotenv;
        use diesel::prelude::*;
        use diesel::sqlite::SqliteConnection;

        use std::env;
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let conn = SqliteConnection::establish(&database_url);
        assert!(conn.is_ok());
    }
}
