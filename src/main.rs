use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rand_core::OsRng;
use std::fmt;
use thiserror::Error;
use tokio::task;

#[derive(Debug)]
pub struct ArgonError(argon2::password_hash::Error);

impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ArgonError {}

#[derive(Error, Debug)]
pub enum MyError {
    #[error("Error hashing password: {0}")]
    HashingError(ArgonError),
    #[error("Other error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

const MEMORY_COST: u32 = 45000;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

#[tokio::main]
async fn main() -> Result<(), MyError> {
    let passwords: Vec<String> = (0..50).map(|_| generate_password(16)).collect();

    // Define Argon2 parameters
    let params_result = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN));
    let params = match params_result {
        Ok(params) => params,
        Err(error) => {
            return Err(MyError::Other(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("An error occurred: {}", error),
            ))))
        }
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let tasks = passwords.into_iter().map(|password| {
        let argon2 = argon2.clone();
        task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            // Hash the password and handle any errors
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                // Simplify error handling
                .map_err(|e| MyError::HashingError(ArgonError(e)))
        })
    });

    let results: Result<Vec<_>, _> = futures::future::try_join_all(tasks).await;

    match results {
        Ok(hashes) => {
            for hash in hashes {
                match hash {
                    Ok(hash) => println!("Hashed password: {}", hash),
                    Err(e) => println!("Failed to hash password: {}", e),
                }
            }
            println!("{}", "[LOG] Passwords hashed successfully".green());
        }
        Err(e) => {
            println!("Failed to hash password: {}", e);
        }
    }

    Ok(())
}

fn generate_password(length: u8) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length as usize)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password() {
        let password = generate_password(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_argon_error_display() {
        let error = argon2::password_hash::Error::Password;
        let argon_error = ArgonError(error);
        assert_eq!(format!("{}", argon_error), "invalid password");
    }

    #[tokio::test]
    async fn test_hash_password() {
        let password = generate_password(16);
        let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let result = argon2.hash_password(password.as_bytes(), &salt);
        assert!(result.is_ok());
    }
}
