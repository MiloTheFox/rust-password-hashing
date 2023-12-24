// Importing necessary modules and functions
use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, ParamsBuilder,
};
use rand_core::OsRng; // For generating random numbers
use zeroize::Zeroize; // For securely erasing sensitive data

use rpassword::prompt_password; // Used to hide the password input

use std::error::Error;
use std::fmt;

// Import colored module for colored output
use colored::Colorize;


// Define a new error type for Argon2 errors
#[derive(Debug)]
pub struct ArgonError(pub argon2::password_hash::Error);

// Define a new error type for our application
#[derive(Debug)]
pub enum MyError {
    Argon(ArgonError),
    VerificationFailed,
}

impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::Argon(e) => write!(f, "Argon2 error: {}", e),
            MyError::VerificationFailed => write!(f, "Password verification failed"),
        }
    }
}

impl Error for MyError {}

// Define a macro for logging messages
macro_rules! log {
    ($msg:expr) => {
        eprintln!("{}", format!("[LOG] {}", $msg).green());
    };
}

// Define a macro for logging error messages
macro_rules! error {
    ($msg:expr) => {
        eprintln!("{}", format!("[ERROR] {}", $msg).bold().red());
    };
}

// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut password = prompt_password("Please enter your password: ")?;
    let password_trimmed = password.trim();
    if password_trimmed.is_empty() {
        error!("You have to provide a password!");
        return Ok(());
    }

    let password_bytes = password_trimmed.as_bytes();

    let salt = SaltString::generate(&mut OsRng);

    let params = ParamsBuilder::new()
        .m_cost(19) // reduced memory cost
        .t_cost(2) // reduced time cost
        .p_cost(1) // reduced parallelism cost
        .output_len(32) // reduced output length
        .build()
        .expect("Failed to build Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password_bytes, salt.as_salt())
        .expect("Failed to hash password");
    log!("Password hashed successfully");
    println!("{} {}", "[LOG] Generated hash: ".yellow(), password_hash);

    // Verify the password
    if argon2
        .verify_password(password_bytes, &password_hash)
        .is_ok()
    {
        log!("Password verified successfully");
        password.zeroize();
        Ok(())
    } else {
        error!("Password verification failed");
        Err(Box::new(MyError::VerificationFailed))
    }
}
