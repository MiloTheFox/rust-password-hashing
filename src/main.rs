use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use lazy_static::lazy_static;
use passwords::{analyzer, scorer, PasswordGenerator};
use rand_core::OsRng;
use rayon::prelude::*;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroize;

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
    #[error("Error hashing password with salt {salt}: {source}")]
    HashingError {
        source: ArgonError,
        salt: SaltString,
    },
    #[error("Failed to generate password")]
    PasswordGenerationError,
}

const MEMORY_COST: u32 = 50;
const TIME_COST: u32 = 2;
const PARALLELISM: u32 = 2;
const OUTPUT_LEN: usize = 32;

lazy_static! {
    static ref ARGON2: Argon2<'static> = {
        let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
            .expect("Failed to set Argon2 parameters");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    };
}

fn main() -> Result<(), MyError> {
    let passwords = generate_passwords_using_rayon(50, 16)?;
    let rng = OsRng;

    let results: Result<Vec<_>, _> = passwords
        .into_par_iter()
        .map(|(mut password, _)| {
            let salt = SaltString::generate(rng);
            let result = ARGON2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|source| MyError::HashingError {
                    source: ArgonError(source),
                    salt: salt.clone(),
                })
                .map(|hash| hash.to_string());
            password.zeroize();
            result
        })
        .collect();

    match results {
        Ok(hashes) => {
            for hash in hashes {
                println!("Hashed password: {}", hash);
            }
            println!("{}", "[LOG] Passwords hashed successfully".green());
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[inline]
fn generate_password(pg: &PasswordGenerator) -> Result<(String, f64), MyError> {
    let password = pg
        .generate_one()
        .map_err(|_| MyError::PasswordGenerationError)?;
    let analyzed: analyzer::AnalyzedPassword = analyzer::analyze(&password);
    let score = scorer::score(&analyzed);
    Ok((password, score))
}

#[inline]
fn generate_passwords_using_rayon(
    num_passwords: usize,
    length: usize,
) -> Result<Vec<(String, f64)>, MyError> {
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
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PG: PasswordGenerator = PasswordGenerator {
        length: 16,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    };

    #[test]
    fn test_argon_error_display() {
        let error = argon2::password_hash::Error::Password;
        let argon_error = ArgonError(error);
        assert_eq!(format!("{}", argon_error), "invalid password");
    }

    #[test]
    fn test_generate_password() {
        match generate_password(&PG) {
            Ok((password, _score)) => {
                assert!(password.len() == 16 && password.chars().all(|c| c.is_ascii_graphic()));
            }
            Err(e) => {
                panic!("Password generation failed with error: {}", e);
            }
        }
    }

    #[test]
    fn test_hash_password() {
        let (mut password, _score) = match generate_password(&PG) {
            Ok(result) => result,
            Err(e) => panic!("Password generation failed with error: {}", e),
        };

        let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let result = argon2.hash_password(&password.as_bytes(), &salt);
        assert!(result.is_ok());
        password.zeroize();
    }
}
