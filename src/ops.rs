use crate::models::{NewPassword, Password};
use crate::schema::password::dsl::*;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenvy::dotenv;
use std::env;

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
fn get_password(
    connection: &mut SqliteConnection,
    term: &str,
) -> Result<Password, diesel::result::Error> {
    password
        .filter(name.eq(term))
        .select(Password::as_select())
        .first(connection) // here we use first to return only the first record
}
// delete a password given a name, again, not generic.
fn delete_password(
    connection: &mut SqliteConnection,
    term: &str,
) -> Result<usize, diesel::result::Error> {
    diesel::delete(password.filter(name.eq(term))).execute(connection)
}

// test module for CRUD ops
#[cfg(test)]
mod tests {

    use diesel::{SqliteConnection, Connection};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    use crate::models::NewPassword;
    use crate::schema::password::dsl::*;
    use diesel::prelude::*;
    use super::{insert_password, delete_password, get_password};
    
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
    #[test]
    fn create() {
        let mut conn = establish_in_memory_connection();
        insert_test_data(&mut conn);
        assert_eq!(password.count().first::<i64>(&mut conn).unwrap(), 1);
    }
    // tests  start here!
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
        
        let _ = delete_password(&mut conn, "test").unwrap();

        assert_eq!(password.count().first::<i64>(&mut conn).unwrap(), 0);

    }   

}
