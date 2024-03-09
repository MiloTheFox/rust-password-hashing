use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use passwords::{analyzer, scorer, PasswordGenerator};
use rand_core::OsRng;
use rayon::prelude::*;
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

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
    // ... other variants
    #[error("Error hashing password: {0}")]
    HashingError(ArgonError),
    #[error("Other error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

const MEMORY_COST: u32 = 45000;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

fn main() -> Result<(), MyError> {
    let passwords = generate_passwords_using_rayon(50, 16);

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

    let argon2 = Arc::new(Argon2::new(Algorithm::Argon2id, Version::V0x13, params));

    let results: Vec<_> = passwords
        .into_par_iter()
        .map(|(password, _)| {
            let argon2 = Arc::clone(&argon2);
            let rng = OsRng;
            let salt = SaltString::generate(*&rng);
            // Hash the password and handle any errors
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
        })
        .collect();

    for result in results {
        match result {
            Ok(hash) => println!("Hashed password: {}", hash),
            Err(e) => println!("Failed to hash password: {}", e),
        }
    }
    // Log success message
    println!("{}", "[LOG] Passwords hashed successfully".green());

    Ok(())
}

#[inline]
fn generate_password(pg: &PasswordGenerator) -> (String, f64) {
    let password = pg.generate_one().expect("Failed to generate password");
    let analyzed: analyzer::AnalyzedPassword = analyzer::analyze(&password);
    let score = scorer::score(&analyzed);
    (password, score)
}

#[inline]
fn generate_passwords_using_rayon(num_passwords: usize, length: usize) -> Vec<(String, f64)> {
    let pg = PasswordGenerator {
        length,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    };

    (0..num_passwords)
        .into_par_iter()
        .map(|_| generate_password(&pg))
        .collect::<Vec<_>>() // Collect individual results
}

#[cfg(test)]
mod tests {
    use super::*;

    const PG: PasswordGenerator = PasswordGenerator {
        length: 16, // replace `length` with the actual length
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    };

    #[test]
    fn test_generate_password() {
        let (password, _score) = generate_password(&PG); // handle the tuple correctly
        assert!(password.len() == 16 && password.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn test_argon_error_display() {
        let error = argon2::password_hash::Error::Password;
        let argon_error = ArgonError(error);
        assert_eq!(format!("{}", argon_error), "invalid password");
    }

    #[test]
    fn test_hash_password() {
        let (password, _score) = generate_password(&PG); // handle the tuple correctly
        let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let result = argon2.hash_password(password.as_bytes(), &salt);
        assert!(result.is_ok());
    }
}
