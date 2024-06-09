use argon2::password_hash::{Error as PasswordHashError, SaltString};
use thiserror::Error;

#[derive(Debug)]
pub struct ArgonError(pub PasswordHashError);

impl std::fmt::Display for ArgonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ArgonError {}

#[derive(Error, Debug)]
pub enum MyError {
    #[error("Error hashing password with salt {salt}: {source}")]
    HashingError {
        source: ArgonError,
        salt: SaltString,
    },
    #[error("Failed to generate password")]
    PasswordGenerationError,
}
