use colored::Colorize;
pub fn checking(message: &str) {
    println!("{}: {}", "checking".yellow().bold(), message);
}
pub fn success(message: &str) {
    println!("{}: {}", "success".green().bold(), message);
}
pub fn error(message: &str) {
    println!("{}: {}", "error".red().bold(), message);
}
