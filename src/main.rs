// Importing necessary modules and functions
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, ParamsBuilder,
};
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
    io::stdout().flush()?; // flush it to the screen

    io::stdin().read_line(&mut password)?; // Read the password from the user
    let password_trimmed = password.trim(); // Trim the password
    let password_bytes: Vec<u8> = password_trimmed.bytes().collect(); // Convert the password to bytes
    if password_bytes.is_empty() {
        error!("You have to provide a password!"); // If no password is provided, log an error
        return Ok(());
    }

    let salt = SaltString::generate(&mut OsRng); // Generate a random salt

    // Define the parameters for the Argon2 algorithm
    let params = ParamsBuilder::new()
        .m_cost(256)
        .t_cost(32)
        .p_cost(16)
        .output_len(64)
        .build();

    // Create a new Argon2 instance
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.map_err(|e| MyError::Argon(ArgonError::from(e)))?,
    );

    // Hash the password
    let password_hash = argon2
        .hash_password(password_trimmed.as_bytes(), salt.as_salt())
        .map_err(|e| MyError::Argon(ArgonError::from(e)))?;
    log!("Password hashed successfully"); // Log a success message
    println!("{} {}", "[LOG] Generated hash: ".yellow(), password_hash); // Print the hashed password

    // Convert the hashed password to a string
    let binding = password_hash.to_string();
    
    // Parse the hashed password
    let parsed_hash =
        PasswordHash::new(&binding).map_err(|e| MyError::Argon(ArgonError::from(e)))?;

    // Verify the password
    if argon2
        .verify_password(password_trimmed.as_bytes(), &parsed_hash)
        .is_ok()
    {
        log!("Password verified successfully"); // Log a success message
        password.zeroize(); // Securely erase the password
        Ok(())
    } else {
        error!("Password verification failed"); // Log an error message
        Err(Box::new(MyError::VerificationFailed)) // Return an error
    }
}
