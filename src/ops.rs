use crate::crypto::{hash, encrypt_if_some};
use crate::models::{NewPassword, Password, PasswordForm};
use crate::schema::password::dsl::*;
use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, AeadCore};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenvy::dotenv;
use std::env;
pub const MASTER_KEYWORD: &str = ".master";

// these functions provide the basic CRUD operations, i.e create, read, update, delete
// currently these functions are not generic, possible todo

// these functions have a connection parameter so that a ":memory:" connection can be based for in-memory testing

// simple function, returns SqliteConnection by reading address from .env
pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect("Error connecting to database")
}
// insert password given an object of type NewPassword and a connection
pub fn insert_password(
    connection: &mut SqliteConnection,
    new_password: NewPassword,
) {
    diesel::insert_into(password)
        .values(&new_password)
        .execute(connection)
        .expect("error inserting password");
}

// get a password given a name of type &str and a connection
pub fn get_password(connection: &mut SqliteConnection, term: &str) -> Option<Password> {
    password
        .filter(name.eq(term))
        .select(Password::as_select())
        .first(connection)
        .optional()
        .expect("error getting password")
}
// delete a password given a name, again, not generic.
pub fn delete_password(connection: &mut SqliteConnection, term: &str) {
    let _ = diesel::delete(password.filter(name.eq(term))).execute(connection);
}
pub fn update_password(connection: &mut SqliteConnection, term: &str, form: PasswordForm) {
    let _ = diesel::update(password.filter(name.eq(term)))
        .set(form)
        .execute(connection)
        .expect("error updating password");
}
pub fn check_master_exists(connection: &mut SqliteConnection) -> bool {
    let res = get_password(connection, MASTER_KEYWORD);
    match res {
        Some(_) => true,
        None => false,
    }
}

pub fn authenticate(connection: &mut SqliteConnection, master_password: &[u8]) -> bool {
    let res =
        get_password(connection, MASTER_KEYWORD).expect("Error: Master password does not exist");
    hex::decode(
        res.pass
            .expect("Error: Master record exists but has no password"),
    )
    .unwrap()
        == hash(master_password).to_vec()
}
pub fn insert_master_password(connection: &mut SqliteConnection, data: &[u8]) {
    let master_password = hash(data);
    let encoded = hex::encode(master_password);
    let data = Some(encoded.as_str());
        diesel::insert_into(password)
        .values(NewPassword {
            name: MASTER_KEYWORD,
            username: None,
            email: None,
            pass: data,
            notes: None,
            aes_nonce: "",
        })
        .execute(connection)
        .expect("error inserting master password");
}

pub fn encrypt_and_insert_password(
    connection: &mut SqliteConnection,
    master_password: &str,
    new_name: &str,
    new_username: Option<&str>,
    new_email: Option<&str>,
    new_pass: Option<&str>,
    new_notes: Option<&str>,
    
) {

    let nonce = Aes256Gcm::generate_nonce(OsRng);

    let encrypted_username = encrypt_if_some(new_username, &master_password, nonce, new_name);
    
    let encrypted_email = encrypt_if_some(new_email, &master_password, nonce, &new_name);
    let encrypted_pass = encrypt_if_some(new_pass, &master_password, nonce, &new_name);
    let encrypted_notes = encrypt_if_some(new_notes, &master_password, nonce, &new_name);

    let encoded_nonce = hex::encode(nonce);
    let new_password = NewPassword {
        name: new_name,
        username: encrypted_username.as_deref(),
        email: encrypted_email.as_deref(),
        pass: encrypted_pass.as_deref(),
        notes: encrypted_notes.as_deref(),
        aes_nonce: &encoded_nonce,
    };
    insert_password(connection, new_password);

}


// test module for CRUD ops

#[cfg(test)]
mod tests {
    use super::{delete_password, get_password, insert_password, update_password};
    use crate::crypto::generate_key;
    use crate::models::{NewPassword, PasswordForm};
    use crate::schema::password::dsl::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::consts::{B1, B0};
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use diesel::prelude::*;
    use diesel::{Connection, SqliteConnection};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    use sha2::digest::typenum::{UInt, UTerm};

    // the embed_migrations! macro will generate a constant value containing migrations, which are
    // stored in the binary
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
    // testing only function that creates a new connection in memory,
    // and applies the migrations we generated from the embed_migrations! macro
    fn establish_in_memory_connection() -> SqliteConnection {
        let mut connection = SqliteConnection::establish(":memory:").unwrap();
        connection.run_pending_migrations(MIGRATIONS).unwrap();
        connection
    }
    // testing-only function that inserts 1 test record with some data into a table
    // none of this testing data is encrypted
    fn insert_test_data(connection: &mut SqliteConnection) {
        // test data
        let new_password = NewPassword {
            name: "test",
            username: Some("tester"),
            email: Some("test@test.com"),
            pass: None,
            notes: None,
            aes_nonce: "",
        };
        insert_password(connection, new_password);
    }

    #[test]
    fn create() {
        let mut conn = establish_in_memory_connection();
        insert_test_data(&mut conn);
        assert_eq!(password.count().first::<i64>(&mut conn).unwrap(), 1);
    }
    #[test]
    fn read() {
        let mut conn = establish_in_memory_connection();

        insert_test_data(&mut conn);

        let res = get_password(&mut conn, "test").unwrap();
        assert_eq!(res.username, Some("tester".to_string()));
    }
    #[test]
    fn delete() {
        let mut conn = establish_in_memory_connection();

        insert_test_data(&mut conn);

        let _ = delete_password(&mut conn, "test");

        assert_eq!(password.count().first::<i64>(&mut conn).unwrap(), 0);
    }
    #[test]
    fn update() {
        let mut conn = establish_in_memory_connection();
        insert_test_data(&mut conn);
        update_password(
            &mut conn,
            "test",
            PasswordForm {
                name: Some("foo"),
                username: None,
                email: None,
                pass: None,
                notes: None,
                aes_nonce: "",
            },
        );
        let res = get_password(&mut conn, "foo");
        assert_eq!(res.unwrap().name, "foo");
    }
    #[test]
    fn authenticate() {
        let mut conn = establish_in_memory_connection();
        super::insert_master_password(&mut conn, b"mymasterpassword");
        assert!(super::authenticate(&mut conn, b"mymasterpassword"));
    }
    #[test]
    fn failed_authentication() {
        let mut conn = establish_in_memory_connection();
        super::insert_master_password(&mut conn, b"mymasterpassword");
        assert!(!super::authenticate(&mut conn, b"randomguess"));
    }
    #[test]
    fn read_encrypted_data() {
        let mut conn = establish_in_memory_connection();
        super::encrypt_and_insert_password(&mut conn, "mymasterpassword", "tester", Some("test"), Some("tester@test.com"), Some("secret_pass123!"), None);

        let key = generate_key(b"mymasterpassword", b"tester");
        let cipher = Aes256Gcm::new(&key.into());

        let res = get_password(&mut conn, "tester").unwrap();

        let nonce = hex::decode(res.aes_nonce).unwrap();

        let ciphertext = hex::decode(res.pass.expect("no password")).expect("error decoding password");

        let plaintext = cipher.decrypt(GenericArray::from_slice(&nonce), ciphertext.as_ref()).expect("asd");
        assert_eq!(plaintext, b"secret_pass123!");




    }

}