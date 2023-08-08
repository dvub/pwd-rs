mod args;
pub mod models;
pub mod schema;
pub mod ops;
pub mod crypto;

use diesel::SqliteConnection;
use ops::*;
use schema::password::dsl::*;
use args::PwdArgs;
use clap::Parser;

use crypto::hash;

fn main() {
    let args = PwdArgs::parse();
    let mut conn = establish_connection();
    match validate(&mut conn, args.master_password.as_bytes()) {
        true => {
            println!("validated!");
        }
        false => {
            println!("validation failed..");
        }
    }

}