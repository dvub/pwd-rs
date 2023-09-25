mod args;
pub mod console;
pub mod crypto;
pub mod models;
pub mod ops;
pub mod schema;
use args::PwdArgs;
use clap::Parser;
use colored::Colorize;
use console::{checking, error, success};
use ops::*;
use ops::{check_password_exists, insert_master_password};

use crate::args::{PasswordCommands, PasswordTypes};

fn main() {
    let args = PwdArgs::parse();
    // make it look pretty :)
    // i took all the time to write this shit code so the final app better look nice
    println!(
        "{}",
        "
    ___            _            
   | _ \\__ __ ____| |___ _ _ ___
   |  _/\\ V  V / _` |___| '_(_-<
   |_|   \\_/\\_/\\__,_|   |_| /__/"
            .bold()
    );
    println!("");
    println!("{} {}!", "Welcome to".italic(), "pwd-rs".bold().green());
    println!("");
    // a lot of rather busy work to do here,
    // mostly checking master record, connecting to database, etc.

    // create connection
    let conn = establish_connection();

    let Ok(mut conn) = conn else {
        error("could not connect application to local SQLite database");
        return;
    };
    success("connected to local SQLite database");

    // this is some logic to check create a new master record if one doesn't already exist
    // the logic for this ended up being really complicated
    checking("master record");
    let master_exists = check_password_exists(&mut conn, MASTER_KEYWORD);
    match master_exists {
        Ok(exists) => {
            if let PasswordCommands::Add { ref name, .. } = args.command {
                if name == ops::MASTER_KEYWORD {
                    if exists {
                        error("master record already exists");
                    } else {
                        let _ = insert_master_password(&mut conn, args.master_password.as_bytes());
                        success("created new master record");
                    }
                }
                return;
            }
            if !exists {
                error("\r No master record exists. Use pwd-rs -P <your-master-password> add -N master.");
                return;
            }
        }
        Err(_) => {
            error("error checking master record");
            return;
        }
    }
    success("found master record");

    checking("authenticating with master record");
    if let Ok(t) = authenticate(&mut conn, args.master_password.as_bytes()) {
        if !t {
            error("incorrect master password");
            return;
        }
    }

    success("authenticated using master record");
    println!();

    // a lot of checks and authentication is finall done,
    // now we have to get to actually doing the command the user wants

    match args.command {
        args::PasswordCommands::Add {
            name,
            email,
            username,
            notes,
            password_type,
        } => {
            checking("password name is available");
            match check_password_exists(&mut conn, name.as_str()) {
                Ok(res) => {
                    if res == true {
                        error("password with this name already exists \n\t modify or delete existing password instead");
                        return;
                    }
                }
                Err(_) => {
                    error("error checking password exists");
                }
            }
            success("password with this name is available");

            let new_pass = match password_type {
                Some(password_type) => match password_type {
                    PasswordTypes::Manual { password } => Some(password),
                    PasswordTypes::Auto { length: _ } => Some("".to_string()),
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
            success("inserted new password into SQLite database");
        }
        args::PasswordCommands::Get { name } => {
            let result = read_and_decrypt(&mut conn, &args.master_password, &name);
            match result {
                Ok(v) => match v {
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
                },
                Err(_) => error("error reading password"),
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
