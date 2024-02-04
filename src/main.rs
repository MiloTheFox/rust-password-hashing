use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use futures;
use rand_core::OsRng;
use tokio::task;
use zeroize::Zeroize;

#[derive(Debug)]
enum MyError {
    ArgonError(argon2::password_hash::Error),
}

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MyError::ArgonError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for MyError {}

const MEMORY_COST: u32 = 65534;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let salt = SaltString::generate(&mut OsRng);

    let mut passwords: Vec<String> = vec![
        "YourFirstPassword".to_string(),
        "YourSecondPassword".to_string(),
        "YourThirdPassword".to_string(),
        "4thPassword".to_string(),
        // etc.
    ];

    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
        .map_err(|e| MyError::ArgonError(e.into()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let tasks = passwords.clone().into_iter().map(|password| {
        let argon2 = argon2.clone();
        let salt = salt.clone();
        task::spawn(async move {
            match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(hash) => Ok(hash.to_string()), // use debug formatting here
                Err(e) => Err(e),
            }
        })
    });

    let results: Result<Vec<_>, _> = futures::future::join_all(tasks).await.into_iter().collect();

    passwords.zeroize();

    match results {
        Ok(hashes) => {
            for hash in hashes {
                match &hash {
                    Ok(h) => println!("Hashed password: {}", h),
                    Err(e) => println!("Failed to hash password: {:?}", e),
                }
            }
            println!("{}", "[LOG] Passwords hashed successfully".green());
        }
        Err(e) => {
            println!("Failed to hash password: {:?}", e);
        }
    }
    Ok(())
}
