use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use passwords::{analyzer, scorer, PasswordGenerator};
use rand_core::OsRng;
use rayon::prelude::*;
use zeroize::Zeroize;

mod errors;
use errors::{MyError};

// Configuration Constants
const MEMORY_COST: u32 = 128 * 2048; // 256 MiB
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 4;
const OUTPUT_LEN: usize = 32;
const MAX_PASSWORD_OUTPUT: u32 = 20;
const PASSWORD_LENGTH: usize = 32;

type PasswordWithScore = (String, f64);

fn main() -> Result<(), MyError> {
    let argon2 = create_argon2();

    // Step 1: Generate passwords in parallel
    let generated_passwords: Result<Vec<PasswordWithScore>, MyError> = 
        (0..MAX_PASSWORD_OUTPUT)
            .into_par_iter()
            .map(|_| {
                let generator = create_password_generator();
                let (password, score) = generate_password(&generator)?;
                println!("Generated password: {} (score: {:.2})", password.green(), score);
                Ok((password, score))
            })
            .collect();

    let generated_passwords = generated_passwords?;

    // Step 2: Hash passwords in parallel
    let hashed_passwords: Result<Vec<_>, MyError> = generated_passwords
        .into_par_iter()
        .map(|(mut password, _score)| {
            let salt = SaltString::generate(&mut OsRng);
            let hash = hash_password(&argon2, &password, &salt);
            password.zeroize(); // Zeroize right after hashing
            hash
        })
        .collect();

    // Step 3: Output results
    match hashed_passwords {
        Ok(hashes) => {
            hashes.into_iter().for_each(|hash| {
                println!("Hash output: {}", hash);
            });
            println!("{}", "[LOG] All passwords have been hashed successfully".green());
            Ok(())
        }
        Err(e) => Err(e),
    }
}


fn create_argon2() -> Argon2<'static> {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
        .expect("Failed to set Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_password(argon2: &Argon2<'_>, password: &str, salt: &SaltString) -> Result<String, MyError> {
    argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| MyError::HashingError {
            source: e.into(), // automatically converts to ArgonError if From is implemented
            salt: salt.clone(),
        })
        .map(|hash| hash.to_string())
}

fn create_password_generator() -> PasswordGenerator {
    PasswordGenerator {
        length: PASSWORD_LENGTH,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    }
}

fn generate_password(password_gen: &PasswordGenerator) -> Result<PasswordWithScore, MyError> {
    let password = password_gen
        .generate_one()
        .map_err(|_| MyError::PasswordGenerationError)?;
    let analyzed = analyzer::analyze(&password);
    let score = scorer::score(&analyzed);
    Ok((password, score))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORDGENERATOR: PasswordGenerator = PasswordGenerator {
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
    fn test_generate_password() {
        match generate_password(&PASSWORDGENERATOR) {
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
        let (mut password, _score) = match generate_password(&PASSWORDGENERATOR) {
            Ok(result) => result,
            Err(e) => panic!("Password generation failed with error: {}", e),
        };

        let argon2 = create_argon2();
        let salt = SaltString::generate(&mut OsRng);
        let result = argon2.hash_password(&password.as_bytes(), &salt);
        assert!(result.is_ok());
        password.zeroize();
    }
}
