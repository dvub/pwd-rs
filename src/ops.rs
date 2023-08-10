use crate::crypto::{hash, derive_and_encrypt};
use crate::models::{NewPassword, Password, PasswordForm};
use crate::schema::password::dsl::*;
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
) -> Result<usize, diesel::result::Error> {
    diesel::insert_into(password)
        .values(&new_password)
        .execute(connection)
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
    insert_password(
        connection,
        NewPassword {
            name: super::MASTER_KEYWORD,
            username: None,
            email: None,
            pass: data,
            notes: None,
            aes_nonce: None,
        },
    )
    .unwrap();
}

// test module for CRUD ops

#[cfg(test)]
mod tests {
    use super::{delete_password, get_password, insert_password, update_password};
    use crate::crypto::hash;
    use crate::models::{NewPassword, PasswordForm};
    use crate::schema::password::dsl::*;
    use diesel::prelude::*;
    use diesel::{Connection, SqliteConnection};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

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
            aes_nonce: None,
        };
        insert_password(connection, new_password).unwrap();
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
                aes_nonce: None,
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
}
