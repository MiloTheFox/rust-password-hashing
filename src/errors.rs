use argon2::password_hash::Error as PasswordHashError;
use std::fmt;
use thiserror::Error;

#[derive(Debug)]
pub struct ArgonError(pub PasswordHashError);

impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ArgonError {}

#[derive(Error, Debug)]
pub enum MyError {
    #[error("Error hashing password with salt {salt}: {source}")]
    HashingError {
        source: ArgonError,
        salt: argon2::password_hash::SaltString,
    },
    #[error("Failed to generate password")]
    PasswordGenerationError,
}
