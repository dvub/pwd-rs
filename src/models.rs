use diesel::prelude::*;
use crate::schema::password;
// this is the main struct that provides the table and columns
// suitable for selects and queries, made evident by the derivations
#[derive(Queryable, Selectable)]
#[diesel(table_name = password)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Password {
    pub id: i32,
    pub name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub pass: Option<String>,
    pub notes: Option<String>,
    pub aes_nonce: String,
}
// struct to insert a new password
// does NOT include id, as id is auto incremented and should almost never be manually set
#[derive(Insertable)]
#[diesel(table_name = password)]
pub struct NewPassword<'a> {
    pub name: &'a str,
    pub username: Option<&'a str>,
    pub email: Option<&'a str>,
    pub pass: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub aes_nonce: &'a str,
}
// struct to update passwords
// all fields are optional,
// in diesel, if None is supplied to a struct with AsChangeset,
// the column will simply not be updated
#[derive(AsChangeset)]
#[diesel(table_name = password)]
pub struct PasswordForm<'a> {
    pub name: Option<&'a str>,
    pub username: Option<&'a str>,
    pub email: Option<&'a str>,
    pub pass: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub aes_nonce: &'a str,
}
