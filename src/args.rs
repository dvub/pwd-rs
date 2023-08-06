use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pwd-rs")]
#[command(author = "dvub <dvubdevs@gmail.com>")]
#[command(version = "1.0.0")]
#[command(about = "Client-side password management/generator CLI tool built with Rust.", long_about = None)]

pub struct PwdArgs {
    /// Command to run
    #[command(subcommand)]
    pub command: PasswordCommands,

    /// Master password
    #[arg(short = 'P', long)]
    pub master_password: String,
}
#[derive(Subcommand)]
pub enum PasswordCommands {
    /// Add a new password
    Add(AddArgs),

    /// Search for an existing password
    Get(GetArgs),
}

#[derive(Args)]
pub struct GetArgs {
    /// The password name to search for
    #[arg(short, long)]
    pub name: String,
}

#[derive(Args)]
pub struct AddArgs {
    /// Password name
    #[arg(short, long)]
    pub name: String,
    /// Optional email address
    #[arg(short, long)]
    pub email: Option<String>,
    /// Optional username
    #[arg(short, long)]
    pub username: Option<String>,
    /// Optional notes
    #[arg(short = 't', long)]
    pub notes: Option<String>,
    /// Optional method of password generation
    #[command(subcommand)]
    pub password_type: Option<PasswordTypes>,
}

#[derive(Subcommand)]
pub enum PasswordTypes {
    /// Manually type a password
    Manual(ManualArgs),
    /// Automatically generate a strong password (recommended)
    Auto(AutoArgs),
}

#[derive(Args)]
pub struct ManualArgs {
    /// Password
    #[arg(short, long)]
    password: String,
}
#[derive(Args)]
pub struct AutoArgs {
    /// Password length, max 32 characters
    #[arg(short, long, default_value_t = 10)]
    length: usize,
}
