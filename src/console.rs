use colored::Colorize;

use crate::models::Password;
pub fn checking(message: &str) {
    println!("{}: {}", "checking".yellow().bold(), message);
}
pub fn success(message: &str) {
    println!("{}: {}", "success".green().bold(), message);
}
pub fn error(message: &str) {
    println!("{}: {}", "error".red().bold(), message);
}
pub fn print_pass(password: Password) {
    println!(" --- {}: {} --- ", "name".bold(), password.name);
    let data = vec![
        password.email,
        password.username,
        password.pass,
        password.notes,
    ];
    // FP (ftw) to check if the array of password fields contains only `none` and print a message
    if data.iter().all(|field| field.is_none()) {
        println!();
        println!("no other data found for this record");
    }

    for (index, field) in data.iter().enumerate() {
        match field {
            Some(m) => {
                let name = match index {
                    0 => "email".bold().bright_red(),
                    1 => "username".bold(),
                    2 => "password".bold().red(),
                    3 => "notes".bold(),
                    _ => "".bold(),
                };
                println!("{}: {}", name, m);
            }
            None => {}
        }
    }
}
