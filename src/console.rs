use colored::Colorize;
pub fn checking(message: &str) {
    print!("{}: {}", "checking".yellow().bold(), message);
    print!("\r");
}
pub fn success(message: &str) {
    println!("{}: {}", "success".green().bold(), message);
}
pub fn error(message: &str) {
    println!("{}: {}", "error".red().bold(), message);
}
