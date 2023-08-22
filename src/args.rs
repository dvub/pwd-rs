use clap::{Parser, Subcommand};

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
    Add {
        /// Password name
        #[arg(short = 'N', long)]
        name: String,
        /// Optional email address
        #[arg(short, long)]
        email: Option<String>,
        /// Optional username
        #[arg(short, long)]
        username: Option<String>,
        /// Optional notes
        #[arg(short = 'n', long)]
        notes: Option<String>,
        /// Optional method of password generation
        #[command(subcommand)]
        password_type: Option<PasswordTypes>,
    },

    /// Search for an existing password
    Get {
        /// The password name to search for
        #[arg(short = 'N', long)]
        name: String,
    },
    List
}
#[derive(Subcommand)]
pub enum PasswordTypes {
    /// Manually type a password
    Manual {
        /// Password
        #[arg(short, long)]
        password: String,
    },
    /// Automatically generate a strong password (recommended)
    Auto {
        /// Password length, max 32 characters
        #[arg(short, long, default_value_t = 10)]
        length: usize,
    },
}
