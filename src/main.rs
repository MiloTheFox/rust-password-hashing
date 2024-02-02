use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use log::error;
use rand_core::OsRng;
use rayon::prelude::*; // import rayon prelude
use std::error::Error;
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug)]
struct MyError {
    inner: argon2::password_hash::Error,
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl Error for MyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

const MEMORY_COST: u32 = 65534;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a single salt for all password hashes
    let salt = SaltString::generate(&mut OsRng);

    // Create a vector of passwords to hash
    let mut passwords: Vec<String> = vec![
        "YourFirstPassword".to_string(),
        "YourSecondPassword".to_string(),
        "YourThirdPassword".to_string(),
        "4thPassword".to_string(),
        // etc.
    ];

    let params = match Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN)) {
        Ok(params) => params,
        Err(e) => return Err(Box::new(MyError { inner: e.into() })),
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use rayon to hash the passwords in parallel
    let result: Result<Vec<_>, _> = passwords
        .par_iter()
        .map(|password| argon2.hash_password(password.as_bytes(), &salt))
        .collect();

    // Zeroize passwords after use
    passwords.zeroize();

    // Handle the result of the parallel operation
    match result {
        Ok(hashes) => {
            // Log the generated hashes (outside the parallel loop)
            for hash in &hashes {
                println!("Hashed password: {}", hash.to_string());
            }

            println!("{}", "[LOG] Passwords hashed successfully".green());
            Ok(())
        }
        Err(e) => {
            error!("Failed to generate hash: {}", e);
            Err(Box::new(MyError { inner: e.into() }))
        }
    }
}
