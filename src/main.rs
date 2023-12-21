use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use std::error::Error;
use std::io::{self, Write};

use std::{error, fmt};

#[derive(Debug)]
struct ArgonError(argon2::password_hash::Error);

impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl error::Error for ArgonError {}

impl From<argon2::password_hash::Error> for ArgonError {
    fn from(err: argon2::password_hash::Error) -> ArgonError {
        ArgonError(err)
    }
}

macro_rules! log {
    ($msg:expr) => {
        eprintln!("[LOG] {}", $msg);
    };
}

macro_rules! error {
    ($msg:expr) => {
        eprintln!("[ERROR] {}", $msg);
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut password = String::new();
    print!("Please enter your password: ");
    io::stdout().flush()?; // flush it to the screen

    io::stdin().read_line(&mut password)?;
    let password = password.trim().as_bytes();
    if password.is_empty() {
        error!("You have to provide a password!");
        return Ok(());
    }

    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2
        .hash_password(password, salt.as_salt())
        .map_err(ArgonError)?;
    log!("Password hashed successfully");
    eprintln!("[LOG] Generated hash: {}", password_hash);

    // Verify password against PHC string.
    let binding = password_hash.to_string();
    let parsed_hash = PasswordHash::new(&binding).map_err(ArgonError)?;

    assert!(argon2.verify_password(password, &parsed_hash).is_ok());
    log!("Password verified successfully");

    Ok(())
}
