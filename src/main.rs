mod args;
pub mod models;
pub mod schema;
pub mod ops;
pub mod crypto;

use crypto::derive_and_encrypt;
use ops::*;
use args::PwdArgs;
use clap::Parser;

use ops::{check_master_exists, insert_master_password};



fn main() {
    let args = PwdArgs::parse();
    // create connection
    println!("Retrieving database..");
    let mut conn = establish_connection();
    println!("Connected to database!\n");

    println!("Checking for master record...");
    let master_exists = check_master_exists(&mut conn);

    match args.command {
        args::PasswordCommands::Add {name, email, username, notes, password_type} => {
            // 
            if name == ops::MASTER_KEYWORD {
                if master_exists {
                    println!("Master record already exists.");
                } else {
                    insert_master_password(&mut conn, args.master_password.as_bytes());
                    println!("Created new master record.");
                }
                return;
            }

            if !master_exists {
                println!("Master record does not exist. Run 'pwd-rs -P <master_password> --name .master' to create a master record.");
                return;
            } 

            println!("Found master record!");

            if !authenticate(&mut conn, args.master_password.as_bytes()) {
                println!("Incorrect master password.");
                return;
            }

            println!("Successfully authenticated using master record.");
        }
        args::PasswordCommands::Get { name } => {

        }
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    PwdArgs::command().debug_assert()
}
