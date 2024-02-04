// Import necessary libraries
use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use futures;
use rand_core::OsRng;
use tokio::task;
use zeroize::Zeroize;

// Define a custom error type
#[derive(Debug)]
enum MyError {
    ArgonError(argon2::password_hash::Error),
}

// Implement the Display trait for MyError
impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MyError::ArgonError(e) => write!(f, "{}", e),
        }
    }
}

// Implement the Error trait for MyError
impl std::error::Error for MyError {}

// Define constants for Argon2 parameters
const MEMORY_COST: u32 = 65534;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

// Main function
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Generate a new salt string
    let salt = SaltString::generate(&mut OsRng);

    // Define a vector of passwords
    let mut passwords: Vec<String> = vec![
        "YourFirstPassword".to_string(),
        "YourSecondPassword".to_string(),
        "YourThirdPassword".to_string(),
        "4thPassword".to_string(),
        // etc.
    ];

    // Define Argon2 parameters
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
        .map_err(|e| MyError::ArgonError(e.into()))?;

    // Create a new Argon2 instance
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Create tasks for each password to hash
    let tasks = passwords.clone().into_iter().map(|password| {
        let argon2 = argon2.clone();
        let salt = salt.clone();
        task::spawn(async move {
            // Hash the password and handle any errors
            match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(hash) => Ok(hash.to_string()),
                Err(e) => Err(e),
            }
        })
    });

    // Wait for all tasks to complete and collect the results
    let results: Result<Vec<_>, _> = futures::future::join_all(tasks).await.into_iter().collect();

    // Zeroize the passwords for security
    passwords.zeroize();

    // Handle the results
    match results {
        Ok(hashes) => {
            // Print each hashed password or any errors
            for hash in hashes {
                match &hash {
                    Ok(h) => println!("Hashed password: {}", h),
                    Err(e) => println!("Failed to hash password: {:?}", e),
                }
            }
            // Log success message
            println!("{}", "[LOG] Passwords hashed successfully".green());
        }
        Err(e) => {
            // Log error message
            println!("Failed to hash password: {:?}", e);
        }
    }
    Ok(())
}
