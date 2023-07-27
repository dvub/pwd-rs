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
    /// Notes
    #[arg(short = 't', long)]
    pub notes: Option<String>,
    #[command(subcommand)]
    pub password_type: PasswordTypes,
}


#[derive(Subcommand)]
pub enum PasswordTypes {
    /// Manually type a password
    Manual(ManualArgs),
    /// Automatically generate a strong password
    Auto(AutoArgs),
}
#[derive(Args)]
pub struct ManualArgs {

}
#[derive(Args)]
pub struct AutoArgs {
    
}
