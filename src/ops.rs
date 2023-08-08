use crate::models::{NewPassword, Password, PasswordForm};
use crate::schema::password::dsl::*;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenvy::dotenv;
use std::env;
use crate::crypto::hash;

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

pub fn validate(connection: &mut SqliteConnection, master_password: &[u8]) -> bool {
    let res = get_password(connection, ".master");
    match res {
        Some(val) => {
            hex::decode(val.pass.unwrap()).unwrap() == hash(master_password).to_vec()
        }
        None => {
            println!("No master password exists in the database.\nRun the application again and pass in \".master\" as the password name to generate a master password.");
            false
        }
    }
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
            kdf_salt: None,
            aes_nonce: None,
        };
        insert_password(connection, new_password).unwrap();
    }
    fn insert_master_password(connection: &mut SqliteConnection) {
        let master_password = hash("mymasterpassword".as_bytes());
        let encoded = hex::encode(master_password);
        let data = Some(encoded.as_str());
        insert_password(
            connection,
            NewPassword {
                name: ".master",
                username: None,
                email: None,
                pass: data,
                notes: None,
                kdf_salt: None,
                aes_nonce: None,
            },
        ).unwrap();
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
                kdf_salt: None,
                aes_nonce: None,
            },
        );
        let res = get_password(&mut conn, "foo");
        assert_eq!(res.unwrap().name, "foo");
    }
    #[test]
    fn validation() {
        let mut conn = establish_in_memory_connection();
        insert_master_password(&mut conn);
        assert_eq!(super::validate(&mut conn, "mymasterpassword".as_bytes()), true);
        assert_eq!(super::validate(&mut conn, "randomguess123".as_bytes()), false);
    }
}
