use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pwd-rs")]
#[command(author = "dvub <dvubdevs@gmail.com>")]
#[command(version = "1.0.0")]
#[command(about = "Client-side password management/generator CLI tool built with Rust.", long_about = None)]
pub struct PwdArgs {
    /// Command to run
    #[command(subcommand)]
    pub command: Commands,
    /// Master password
    #[arg(short, long)]
    pub master_password: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new password or note
    Add(AddArgs),
    /// Read an existing password from database
    Get(GetArgs),
    //Edit an existing password
    // Edit(EditArgs),
}
#[derive(Args)]
pub struct GetArgs {
    /// The password name to search for
    #[arg(short, long)]
    pub name: String,
}

#[derive(Args)]
pub struct AddArgs {
    /// Name, primarily used for searching passwords
    #[arg(short, long)]
    pub name: String,
    /// Email address
    #[arg(short, long)]
    pub email: Option<String>,
    /// Username
    #[arg(short, long)]
    pub username: Option<String>,
    /// Additional notes
    #[arg(short = 't', long)]
    pub notes: Option<String>,
    
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
    /// Password to use
    #[arg(short, long)]
    password: String,
}
#[derive(Args)]
pub struct AutoArgs {
    /// Password length, max 32 characters
    #[arg(short, long, default_value_t = 10)]
    length: usize,
}
