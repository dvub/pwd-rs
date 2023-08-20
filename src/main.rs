mod args;
pub mod crypto;
pub mod models;
pub mod ops;
pub mod schema;
use args::PwdArgs;
use clap::Parser;
use ops::*;

use ops::{check_master_exists, insert_master_password};

use crate::args::PasswordTypes;

fn main() {
    let args = PwdArgs::parse();
    // create connection
    println!("Retrieving database..");
    let mut conn = establish_connection();
    println!("Connected to database!\n");

    println!("Checking for master record...");
    let master_exists = check_master_exists(&mut conn);

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

    match args.command {
        args::PasswordCommands::Add {
            name,
            email,
            username,
            notes,
            password_type,
        } => {
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

            let mut new_pass = Some(String::from(""));

            match password_type {
                Some(password_type) => match password_type {
                    PasswordTypes::Manual { password } => {
                        new_pass = Some(password);
                    }
                    PasswordTypes::Auto { length } => {}
                },
                None => {}
            }
            encrypt_and_insert(
                &mut conn,
                &args.master_password,
                &name,
                username.as_deref(),
                email.as_deref(),
                new_pass.as_deref(),
                notes.as_deref(),
            );
            println!("Successfully inserted a new password!!");
        }
        args::PasswordCommands::Get { name } => {
            let result = read_and_decrypt(&mut conn, &args.master_password, &name);
            match result {
                Some(found_password) => {
                    println!("Found a password with that name! Decrypting now..");
                    println!("{}", found_password.name);
                    println!("{}", found_password.pass.unwrap());
                }
                None => {
                    println!("No password was found with that name.. :[");
                }
            }
        }
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    PwdArgs::command().debug_assert()
}
