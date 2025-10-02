use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::{Colorize, CustomColor};
use passwords::PasswordGenerator;
use rand::rngs::OsRng;
use rayon::prelude::*;
use zeroize::Zeroize;
use zxcvbn::zxcvbn;

mod errors;
use errors::*;

/// Argon2 Memory Cost
const MEMORY_COST: u32 = 256 * 1024;

/// Iterators
const TIME_COST: u32 = 4;

/// Threads
const PARALLELISM: u32 = 4;

/// Length of the hash
const OUTPUT_LEN: usize = 32;

/// Amount of passwords to be generated
const PASSWORD_COUNT: usize = 50;

/// Length of the passwords
const PASSWORD_LENGTH: usize = 32;

type PasswordWithScore = (String, f64);

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const YEAR: u64 = 365 * DAY;
const CENTURY_THRESHOLD: u64 = YEAR * 100;

const HOUR_MAX: u64 = HOUR - 1;
const DAY_MAX: u64 = DAY - 1;
const YEAR_MAX: u64 = YEAR - 1;
const CENTURY_MAX: u64 = CENTURY_THRESHOLD - 1;

fn main() -> Result<(), MyError> {
    let argon2 = create_argon2();

    // Step 1: Generate passwords in parallel
    let generated_passwords: Result<Vec<PasswordWithScore>, MyError> =
        (0..PASSWORD_COUNT)
            .into_par_iter()
            .map(|_| {
                let generator = create_password_generator();
                let (password, score) = generate_password(&generator)?;
                println!(
                    "Generated password: {} (zxcvbn score: {:.0}/4)",
                    password.green(),
                    score
                );
                Ok((password, score))
            })
            .collect();

    let generated_passwords = generated_passwords?;

    // Step 2: Hash passwords in parallel
    let hashed_passwords: Result<Vec<_>, MyError> = generated_passwords
        .into_par_iter()
        .map(|(mut password, _score)| {
            let salt = SaltString::try_from_rng(&mut OsRng)?;
            let hash = hash_password(&argon2, &password, &salt)?;
            password.zeroize();
            Ok(hash)
        })
        .collect();

    match hashed_passwords {
        Ok(hashes) => {
            hashes.into_iter().for_each(|hash| {
                println!(
                    "Hash output: {}",
                    hash.custom_color(CustomColor::new(255, 165, 0))
                );
            });
            println!(
                "{}",
                "[LOG] All passwords have been hashed successfully".green()
            );
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

/// Hash a password with Argon2 and return the encoded hash string.
fn hash_password(
    argon2: &Argon2<'_>,
    password: &str,
    salt: &SaltString,
) -> Result<String, MyError> {
    let ph = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| MyError::HashingError {
            source: ArgonError {
                message: e.to_string(),
            },
            salt: salt.clone(),
        })?;
    Ok(ph.to_string())
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

fn human_readable_seconds(secs: f64) -> String {
    if !secs.is_finite() { return "unbounded".to_string(); }
    if secs < 1.0 { return "less than a second".to_string(); }

    // Round first and work in integers to avoid repeated float ops.
    let s = secs.round().max(0.0) as u64;

    match s {
        0..=59 => plural(s, "second"),
        60..=HOUR_MAX => plural(s / MINUTE, "minute"),
        HOUR..=DAY_MAX => plural(s / HOUR, "hour"),
        DAY..=YEAR_MAX => plural(s / DAY, "day"),
        YEAR..=CENTURY_MAX => plural(s / YEAR, "year"),
        _ => "centuries".to_string(),
    }
}

fn plural(n: u64, unit: &str) -> String {
    if n == 1 { format!("1 {unit}") } else { format!("{n} {unit}s") }
}


/// Generate a password and score it with zxcvbn.
fn generate_password(
    password_gen: &PasswordGenerator,
) -> Result<PasswordWithScore, MyError> {
    let password = password_gen
        .generate_one()
        .map_err(|_| MyError::PasswordGenerationError)?;

    let estimate = {
        let res = std::panic::catch_unwind(|| zxcvbn(&password, &[]));
        match res {
            Ok(entropy) => entropy,
            Err(_) => {
                return Err(MyError::StrengthEstimationError(crate::errors::ZxcvbnError {
                    message: "zxcvbn crashed during password estimation".to_string(),
                }))
            }
        }
    };

    let score = estimate.score() as u8 as f64;
    let guesses = estimate.guesses() as f64;
    let entropy_bits = if guesses > 0.0 { guesses.log2() } else { 0.0 };
    let guesses_log10 = estimate.guesses_log10();
    let crack_seconds_offline_fast = guesses / 1e10_f64;
    let crack_display_offline_fast = human_readable_seconds(crack_seconds_offline_fast);

    println!(
        "[zxcvbn] score: {:.0}/4 — entropy: {:.2} bits — guesses: {:.0} (~10^{:.2}) — offline_fast: {}",
        score, entropy_bits, guesses, guesses_log10, crack_display_offline_fast
    );

    Ok((password, score))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

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
            Ok((password, score)) => {
                assert!(password.len() == 16 && password.chars().all(|c| c.is_ascii_graphic()));
                assert!((0.0..=4.0).contains(&score));
            }
            Err(e) => {
                panic!("Password generation failed with error: {}", e);
            }
        }
    }

    #[test]
    fn test_hash_password() -> Result<(), Box<dyn std::error::Error>> {
        let (mut password, _score) = match generate_password(&PASSWORDGENERATOR) {
            Ok(result) => result,
            Err(e) => panic!("Password generation failed with error: {}", e),
        };

        let argon2 = create_argon2();
        let salt = SaltString::try_from_rng(&mut OsRng)?;
        let result = argon2.hash_password(password.as_bytes(), &salt);
        assert!(result.is_ok());
        password.zeroize();
        Ok(())
    }
}
