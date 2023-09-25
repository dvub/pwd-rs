// spaghetti code below

use crate::crypto::{decrypt, encrypt, hash};
use crate::models::{NewPassword, Password, PasswordForm};
use crate::schema::password::dsl::*;
use aes_gcm::aead::OsRng;
use aes_gcm::{AeadCore, Aes256Gcm};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenvy::dotenv;
use std::env;

// this is a constant for the name column of the master record.
pub const MASTER_KEYWORD: &str = ".master";

// these functions provide the basic CRUD operations, i.e create, read, update, delete
// currently these functions are not generic, possible todo

// these functions have a connection parameter so that a ":memory:" connection can be based for in-memory testing

// simple function, returns SqliteConnection by reading address from .env
pub fn establish_connection() -> Result<SqliteConnection, ConnectionError> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
}
// insert password given an object of type NewPassword and a connection
pub fn insert_password(
    connection: &mut SqliteConnection,
    new_password: NewPassword,
) -> Result<usize, diesel::result::Error> {
    diesel::insert_into(password)
        .values(&new_password)
        .execute(connection)
}

// get a password given a name of type &str and a connection
pub fn get_password(
    connection: &mut SqliteConnection,
    term: &str,
) -> Result<Option<Password>, diesel::result::Error> {
    password
        .filter(name.eq(term))
        .select(Password::as_select())
        .first(connection)
        .optional()
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

pub fn check_password_exists(
    connection: &mut SqliteConnection,
    term: &str,
) -> Result<bool, diesel::result::Error> {
    let res = get_password(connection, term);
    match res {
        Ok(values) => match values {
            Some(_) => Ok(true),
            None => Ok(false),
        },
        Err(e) => Err(e),
    }
}

pub fn authenticate(
    connection: &mut SqliteConnection,
    master_password: &[u8],
) -> Result<bool, diesel::result::Error> {
    let res = get_password(connection, MASTER_KEYWORD);
    match res {
        Ok(v) => match v {
            Some(value) => Ok(hex::decode(
                value
                    .pass
                    .expect("Error: Master record exists but has no password"),
            )
            .expect("Error decoding")
                == hash(master_password).to_vec()),
            None => Err(diesel::result::Error::NotFound),
        },
        Err(e) => Err(e),
    }
}
pub fn insert_master_password(
    connection: &mut SqliteConnection,
    data: &[u8],
) -> Result<usize, diesel::result::Error> {
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
}
// higher level functions::

// this function will take in the parameters for a new password entry and encrypt each one, then store the values
pub fn encrypt_and_insert(
    connection: &mut SqliteConnection,
    master_password: &str,
    new_name: &str,
    new_username: Option<String>,
    new_email: Option<String>,
    new_pass: Option<String>,
    new_notes: Option<String>,
) {
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let encoded_nonce = hex::encode(nonce);
    // iteration??
    // personally i think this is kind of cool, but it's probably not idiomatic AT ALL..
    let params = vec![new_username, new_email, new_pass, new_notes];
    let mut encrypted_values = Vec::<Option<String>>::new();
    for param in params {
        encrypted_values.push(encrypt(master_password, param, &nonce, new_name));
    }
    // there could be a lot of problems here, like if the order isn't linear like this
    // but since this is all just internal, as long as *I* don't fuck it up it should be fine

    let new_password = NewPassword {
        name: new_name,
        username: encrypted_values[0].as_deref(),
        email: encrypted_values[1].as_deref(),
        pass: encrypted_values[2].as_deref(),
        notes: encrypted_values[3].as_deref(),
        aes_nonce: &encoded_nonce,
    };
    let _ = insert_password(connection, new_password);
}

// this function will search by the term parameter for a password, and decrypt the fields if the password is found.
// if there is no password found, the function returns none.
pub fn read_and_decrypt(
    connection: &mut SqliteConnection,
    master_password: &str,
    term: &str,
) -> Result<Option<Password>, diesel::result::Error> {
    let pwd = get_password(connection, term);
    match pwd {
        Ok(value) => {
            match value {
                Some(value) => {
                    let params = vec![value.username, value.email, value.pass, value.notes];
                    let mut decrypted = Vec::<Option<String>>::new();
                    for param in params {
                        decrypted.push(decrypt(
                            master_password,
                            param,
                            &value.aes_nonce,
                            &value.name,
                        ));
                    }

                    // clone() could be pretty inefficient in some cases, so this might have to be rewritten
                    // todo
                    // (?)
                    Ok(Some(Password {
                        id: value.id,
                        name: value.name,
                        username: decrypted[0].clone(),
                        email: decrypted[1].clone(),
                        pass: decrypted[2].clone(),
                        notes: decrypted[3].clone(),
                        aes_nonce: value.aes_nonce,
                    }))
                }
                None => Ok(None),
            }
        }
        Err(e) => Err(e),
    }
}

// tests
// thank god i can use unwrap or expect or whatever shit fuckery i want down here

#[cfg(test)]
mod tests {
    use crate::schema::password::dsl::*;
    use aes_gcm::aead::{generic_array::GenericArray, Aead};
    use diesel::prelude::*;
    use diesel::{Connection, SqliteConnection};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    // the embed_migrations! macro will generate a constant value containing migrations, which are
    // stored in the binary
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
    // testing only function that creates a new connection in memory,
    // and applies the migrations we generated from the embed_migrations! macro
    fn establish_in_memory_connection() -> SqliteConnection {
        let mut connection =
            SqliteConnection::establish(":memory:").expect("error establishing connection");
        connection
            .run_pending_migrations(MIGRATIONS)
            .expect("error running migrations");
        connection
    }
    // testing-only function that inserts 1 test record with some data into a table
    // none of this testing data is encrypted
    fn insert_test_data(connection: &mut SqliteConnection) {
        use crate::models::NewPassword;
        // test data
        let new_password = NewPassword {
            name: "test",
            username: Some("tester"),
            email: Some("test@test.com"),
            pass: None,
            notes: None,
            aes_nonce: "",
        };
        let _ = super::insert_password(connection, new_password);
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

        let res = super::get_password(&mut conn, "test").unwrap();
        assert_eq!(res.unwrap().username, Some("tester".to_string()));
    }
    #[test]
    fn delete() {
        let mut conn = establish_in_memory_connection();

        insert_test_data(&mut conn);

        let _ = super::delete_password(&mut conn, "test");

        assert_eq!(password.count().first::<i64>(&mut conn).unwrap(), 0);
    }
    #[test]
    fn update() {
        use crate::models::PasswordForm;
        let mut conn = establish_in_memory_connection();
        insert_test_data(&mut conn);
        super::update_password(
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
        let res = super::get_password(&mut conn, "foo");
        assert_eq!(res.unwrap().unwrap().name, "foo");
    }
    #[test]
    fn authenticate() {
        let mut conn = establish_in_memory_connection();
        let _ = super::insert_master_password(&mut conn, b"mymasterpassword");
        assert!(super::authenticate(&mut conn, b"mymasterpassword").unwrap());
    }
    #[test]
    fn failed_authentication() {
        let mut conn = establish_in_memory_connection();
        let _ = super::insert_master_password(&mut conn, b"mymasterpassword");
        assert!(!super::authenticate(&mut conn, b"randomguess").unwrap());
    }
    #[test]
    fn encrypt_and_insert_password() {
        use crate::models::Password;
        use aes_gcm::{Aes256Gcm, Key, KeyInit};

        let mut conn = establish_in_memory_connection();
        // this is the function we are testing
        super::encrypt_and_insert(
            &mut conn,
            "mymasterpassword",
            "salt", // note that i put salt here because i have the pbkdf2 string literal below derived with "salt" as the salt..
            Some("tester1".to_string()),
            None,
            None,
            None,
        );
        // here, the goal is to reproduce the same result from the above function,
        // ideally this code should use as few of my own functions as possible
        // idk if this is true, it just seems smart to me
        let res: Password = password
            .filter(name.eq("salt"))
            .select(Password::as_select())
            .first(&mut conn)
            .expect("error getting password");
        //unwrap hell
        let ciphertext = hex::decode(res.username.unwrap()).unwrap();
        let decoded = hex::decode(res.aes_nonce).unwrap();
        let nonce = GenericArray::from_slice(&decoded);

        // i was too lazy to get a new pbkdf2 string literal so i just copied one from crypto.rs tests
        let key = hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c")
            .unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(&key);

        // decrypt here, too lazy to write good expect()'s
        let val = cipher.decrypt(nonce, ciphertext.as_ref()).expect("ERROR!");

        assert_eq!(val, b"tester1");
    }
    #[test]
    fn read_and_decrypt() {
        let mut conn = establish_in_memory_connection();
        super::encrypt_and_insert(
            &mut conn,
            "mymasterpassword",
            "salt", // note that i put salt here because i have the pbkdf2 string literal below derived with "salt" as the salt..
            Some("tester1".to_string()),
            None,
            None,
            None,
        );
        let res = super::read_and_decrypt(&mut conn, "mymasterpassword", "salt");
        assert_eq!(res.unwrap().unwrap().username.unwrap(), "tester1");
    }
}
