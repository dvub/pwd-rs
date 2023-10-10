pub mod args;
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

use crate::args::{PasswordCommands, PasswordTypes};
use crate::console::print_pass;

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
    checking("connecting to local SQLite database");
    let conn = establish_connection();

    let Ok(mut conn) = conn else {
        error("could not connect application to local SQLite database");
        return;
    };
    success("connected to local SQLite database");

    // this is some logic to check create a new master record if one doesn't already exist
    // the logic for this ended up being really complicated
    checking("master record?");
    let master_exists = check_password_exists(&mut conn, MASTER_KEYWORD);
    match master_exists {
        Ok(master) => {
            if let PasswordCommands::Add { ref name, .. } = args.command {
                if name == ops::MASTER_KEYWORD {
                    if master {
                        error("master record already exists");
                        return;
                    } else {
                        match insert_master_password(&mut conn, args.master_password.as_bytes()) {
                            Ok(_) => {
                                success("created new master record");
                            }
                            Err(_) => {
                                error("error creating new master password");
                            }
                        }
                        return;
                    }
                }
            }
        }
        Err(e) => {
            error("no master record found");
            println!("{}", e);
            return;
        }
    }
    success("found master record");

    checking("authenticating with master record...");
    if let Ok(t) = authenticate(&mut conn, args.master_password.as_bytes()) {
        if !t {
            error("incorrect master password");
            return;
        }
    }

    success("authenticated using master record");
    println!("");
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
            checking("password name is available?");
            match check_password_exists(&mut conn, name.as_str()) {
                Ok(master) => {
                    if master == true {
                        error("password with this name already exists \n\t modify or delete existing password instead");
                        return;
                    }
                }
                Err(_) => error("error checking if password exists"),
            }
            success("password with this name is available");

            let new_pass = match password_type {
                Some(password_type) => match password_type {
                    PasswordTypes::Manual { password } => Some(password),
                    PasswordTypes::Auto { length: _ } => Some("".to_string()),
                },
                None => None,
            };

            match encrypt_and_insert(
                &mut conn,
                &args.master_password,
                &name,
                username,
                email,
                new_pass,
                notes,
            ) {
                Ok(_) => {
                    success("inserted new password into SQLite database");
                }
                Err(_) => error("there was an error inserting the password"),
            }
        }
        args::PasswordCommands::Get { name } => {
            let result = read_and_decrypt(&mut conn, &args.master_password, &name);
            match result {
                Ok(v) => match v {
                    Some(found_password) => {
                        success("found a password");
                        println!("");
                        print_pass(found_password);
                    }
                    None => {
                        error("no password was found with that name");
                    }
                },
                Err(_) => error("error reading password"),
            }
        }
        PasswordCommands::List => match get_all(&mut conn) {
            Ok(passwords) => {
                println!(" --- all passwords (name only) --- ");

                for (i, p) in passwords.iter().enumerate() {
                    println!("{}. {}", i + 1, p.name);
                }
            }
            Err(_) => {
                error("there was an error retrieving all passwords");
            }
        },
    }
    println!("");
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    PwdArgs::command().debug_assert()
}
