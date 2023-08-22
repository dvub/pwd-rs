mod args;
pub mod crypto;
pub mod models;
pub mod ops;
pub mod schema;
use args::PwdArgs;
use clap::Parser;
use ops::*;

use ops::{check_master_exists, insert_master_password};

use crate::args::{PasswordCommands, PasswordTypes};

fn main() {
    let args = PwdArgs::parse();
    println!();
    println!("Welcome to pwd-rs!");
    println!();

    // create connection
    let mut conn = establish_connection();

    println!("Found password database!");
    println!();

    println!("Checking for master record...");
    let master_exists = check_master_exists(&mut conn);
    println!();

    println!("Found master record!");
    println!();

    if !authenticate(&mut conn, args.master_password.as_bytes()) {
        println!("Incorrect master password.");
        return;
    }
    if let PasswordCommands::Add {
        ref name,
        email: _,
        username: _,
        notes: _,
        password_type: _,
    } = args.command
    {
        if name == ops::MASTER_KEYWORD {
            if master_exists {
                println!("Master record already exists.");
            } else {
                insert_master_password(&mut conn, args.master_password.as_bytes());
                println!("Created new master record.");
            }
            return;
        }
    }

    println!("Successfully authenticated using master record.");
    println!();

    match args.command {
        args::PasswordCommands::Add {
            name,
            email,
            username,
            notes,
            password_type,
        } => {
            let new_pass = match password_type {
                Some(password_type) => match password_type {
                    PasswordTypes::Manual { password } => Some(password),
                    PasswordTypes::Auto { length } => Some("".to_string()),
                },
                None => None,
            };
            encrypt_and_insert(
                &mut conn,
                &args.master_password,
                &name,
                username,
                email,
                new_pass,
                notes,
            );
            println!("Successfully inserted a new password!!");
        }
        args::PasswordCommands::Get { name } => {
            let result = read_and_decrypt(&mut conn, &args.master_password, &name);
            match result {
                Some(found_password) => {
                    println!("Found a password with that name! Decrypting...");
                    println!("Reading all data:");
                    println!(" --- Name: {} --- ", found_password.name);
                    let data = vec![
                        found_password.email,
                        found_password.username,
                        found_password.pass,
                        found_password.notes,
                    ];
                    for (index, field) in data.iter().enumerate() {
                        match field {
                            Some(m) => {
                                let name = match index {
                                    0 => "Email",
                                    1 => "Username",
                                    2 => "Password",
                                    3 => "Notes",
                                    _ => "",
                                };
                                println!("{}: {}", name, m);
                            }
                            None => {}
                        }
                    }
                }
                None => {
                    println!("No password was found with that name.. :[");
                }
            }
        }
        PasswordCommands::List => {
            println!("Listing all passwords.");
        }
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    PwdArgs::command().debug_assert()
}
