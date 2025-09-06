use std::fmt;
use argon2::password_hash::SaltString;
use rand_core::OsError;

/// Einfacher Wrapper für Argon2-Fehler
#[derive(Debug)]
pub struct ArgonError {
    pub message: String,
}

impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ArgonError {}

/// Wrapper für zxcvbn-Fehler
#[derive(Debug)]
pub struct ZxcvbnError {
    pub message: String,
}

impl fmt::Display for ZxcvbnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ZxcvbnError {}

/// Zentrale Error-Enum für dein Projekt
#[derive(Debug)]
pub enum MyError {
    PasswordGenerationError,
    HashingError { source: ArgonError, salt: SaltString },
    StrengthEstimationError(ZxcvbnError),
    RngError(OsError),
    Argon2Error(ArgonError),
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MyError::PasswordGenerationError =>
                write!(f, "Password generation failed"),

            MyError::HashingError { source, salt } =>
                write!(f, "Hashing failed (salt: {}): {}", salt.as_str(), source),

            MyError::StrengthEstimationError(source) =>
                write!(f, "Password strength estimation failed: {}", source),

            MyError::RngError(e) =>
                write!(f, "Random number generator failed: {}", e),

            MyError::Argon2Error(e) =>
                write!(f, "Argon2 hashing failed: {}", e),
        }
    }
}

impl std::error::Error for MyError {}

/// Konvertierungen für `?`-Operator

impl From<OsError> for MyError {
    fn from(e: OsError) -> Self {
        MyError::RngError(e)
    }
}

impl From<argon2::password_hash::Error> for MyError {
    fn from(e: argon2::password_hash::Error) -> Self {
        MyError::Argon2Error(ArgonError { message: e.to_string() })
    }
}

impl From<ZxcvbnError> for MyError {
    fn from(e: ZxcvbnError) -> Self {
        MyError::StrengthEstimationError(e)
    }
}
