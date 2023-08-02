use diesel::prelude::*;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::password)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Password {
    pub id: i32,
    pub name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub key: Option<String>,
    pub notes: Option<String>,
    pub kdf_salt: Option<String>,
    pub kdf_iterations : Option<i32>,
    pub aes_nonce: Option<String>,
}