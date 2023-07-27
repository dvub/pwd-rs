mod args;


use args::{PwdArgs, Commands};
use clap::Parser;
fn main() {
    let args = PwdArgs::parse();
    
    match args.command {
        Commands::Add(add_args) => {
            if let Some(_) = add_args.email {
                println!("nice");
            }
            if let Some(_) = add_args.username {

            }
        }
        Commands::Get(_a) => {
            
        }
    }

}

// these tests are mainly to help me understand how all the crates work tbh
//
#[cfg(test)]
mod tests {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, Key,
    };
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    #[test]
    fn aes() {
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
        use hex_literal::hex;
        use pbkdf2::pbkdf2_hmac;
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
}
