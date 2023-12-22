// Importing necessary modules and functions
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, ParamsBuilder,
};

use num_cpus;
use rand_core::OsRng; // For generating random numbers
use std::error::Error;
use std::io::{self, Write}; // For input/output operations
use std::{error, fmt}; // For formatting
use thiserror::Error; // For handling errors
use zeroize::Zeroize; // For securely erasing sensitive data

// Define a new error type for Argon2 errors
#[derive(Debug)]
pub struct ArgonError(pub argon2::password_hash::Error);

// Implement the Display trait for ArgonError
impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implement the Error trait for ArgonError
impl error::Error for ArgonError {}

// Implement From trait for converting argon2::password_hash::Error to ArgonError
impl From<argon2::password_hash::Error> for ArgonError {
    fn from(err: argon2::password_hash::Error) -> ArgonError {
        ArgonError(err)
    }
}

// Implement From trait for converting argon2::Error to ArgonError
impl From<argon2::Error> for ArgonError {
    fn from(err: argon2::Error) -> ArgonError {
        ArgonError(argon2::password_hash::Error::from(err))
    }
}

// Define a new error type for our application
#[derive(Debug, Error)]
pub enum MyError {
    #[error("Argon2 error: {0}")]
    Argon(ArgonError),
    #[error("Password verification failed")]
    VerificationFailed,
}

// Import colored module for colored output
use colored::Colorize;

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
fn main() -> Result<(), Box<dyn Error>> {
    let mut password = String::new();
    print!("Please enter your password: ");
    io::stdout().flush()?;

    io::stdin().read_line(&mut password)?;
    let password_trimmed = password.trim();
    if password_trimmed.is_empty() {
        error!("You have to provide a password!");
        return Ok(());
    }

    let password_bytes = password_trimmed.as_bytes();

    let salt = SaltString::generate(&mut OsRng);

    let params = ParamsBuilder::new()
        .m_cost(128)
        .t_cost(16)
        .p_cost(num_cpus::get().try_into().unwrap())
        .output_len(32)
        .build();

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.map_err(|e| MyError::Argon(ArgonError::from(e)))?,
    );

    let password_hash = argon2
        .hash_password(password_bytes, salt.as_salt())
        .map_err(|e| MyError::Argon(ArgonError::from(e)))?;
    log!("Password hashed successfully");
    println!("{} {}", "[LOG] Generated hash: ".yellow(), password_hash);

    let binding = password_hash.to_string();

    let parsed_hash =
        PasswordHash::new(&binding).map_err(|e| MyError::Argon(ArgonError::from(e)))?;

    if argon2.verify_password(password_bytes, &parsed_hash).is_ok() {
        log!("Password verified successfully");
        password.zeroize();
        Ok(())
    } else {
        error!("Password verification failed");
        Err(Box::new(MyError::VerificationFailed))
    }
}
