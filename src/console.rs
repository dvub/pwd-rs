use std::io::Write;

use colored::Colorize;
pub fn checking(message: &str) {
    print!("{}: {}", "checking".yellow().bold(), message);
    std::io::stdout().flush().unwrap();
}
pub fn success(message: &str) {
    println!("\x1B[1A\x1B[K{}: {}", "success".green().bold(), message);
}
pub fn error(message: &str) {
    println!("{}: {}", "error".red().bold(), message);
}
