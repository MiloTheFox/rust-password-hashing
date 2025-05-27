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


impl From<PasswordHashError> for ArgonError {
    fn from(err: PasswordHashError) -> Self {
        ArgonError(err)
    }
}

#[derive(Debug, Error)]
pub enum MyError {
    #[error("password hashing failed")]
    HashingError {
        #[source]
        source: ArgonError,
        salt: SaltString,
    },

    #[error("password generation failed")]
    PasswordGenerationError,
}
