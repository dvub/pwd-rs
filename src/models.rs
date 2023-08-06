use diesel::prelude::*;
use crate::schema::password;

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
    pub kdf_salt: Option<String>,
    pub aes_nonce: Option<String>,
}
#[derive(Insertable)]
#[diesel(table_name = password)]
pub struct NewPassword<'a> {
    pub name: &'a str,
    pub username: Option<&'a str>,
    pub email: Option<&'a str>,
    pub pass: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub kdf_salt: Option<&'a str>,
    pub aes_nonce: Option<&'a str>,
}
