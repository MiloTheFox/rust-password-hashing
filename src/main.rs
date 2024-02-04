use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use colored::Colorize;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
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

const MEMORY_COST: u32 = 12800;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tasks: Vec<tokio::task::JoinHandle<Result<String, MyError>>> = Vec::new();

    for _ in 0..4 {
        let task = tokio::spawn(async { generate_password(16).await });
        tasks.push(task);
    }

    let results: Vec<Result<String, MyError>> = futures::future::try_join_all(tasks).await?;

    let passwords: Vec<String> = results.into_iter().collect::<Result<Vec<_>, _>>()?;

    // Define Argon2 parameters
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
        .map_err(|e| MyError::ArgonError(e.into()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let tasks = passwords.into_iter().map(|password| {
        let argon2 = argon2.clone();
        task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            // Hash the password and handle any errors
            match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(hash) => Ok(hash.to_string()),
                Err(e) => Err(MyError::ArgonError(e)),
            }
        })
    });

    let results: Result<Vec<Result<String, MyError>>, tokio::task::JoinError> =
        futures::future::try_join_all(tasks).await;

    match results {
        Ok(hashes) => {
            // Filter out errors
            let mut hashes: Vec<_> = hashes.into_iter().filter_map(|x| x.ok()).collect();
            for hash in &hashes {
                println!("Hashed password: {}", hash);
            }
            hashes.zeroize();
            // Log success message
            println!("{}", "[LOG] Passwords hashed successfully".green());
        }
        Err(e) => {
            println!("Failed to hash password: {:?}", e);
        }
    }
    Ok(())
}

async fn generate_password(length: usize) -> Result<String, MyError> {
    Ok(thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use futures::StreamExt;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_hash_password() {
        // Generate passwords asynchronously
        let passwords_result = futures::stream::iter(0..4)
            .map(|_| generate_password(16))
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;

        let mut passwords = Vec::new();
        for result in passwords_result {
            match result {
                Ok(password) => passwords.push(password),
                Err(e) => {
                    panic!("Failed to generate password: {}", e);
                }
            }
        }

        // Define Argon2 parameters
        let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
            .map_err(|e| MyError::ArgonError(e.into()))
            .expect("Failed to create Argon2 parameters");

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let tasks = passwords.into_iter().map(|password| {
            let argon2 = argon2.clone();
            tokio::task::spawn(async move {
                let salt = SaltString::generate(&mut OsRng);
                match argon2.hash_password(password.as_bytes(), &salt) {
                    Ok(hash) => Ok(hash.to_string()),
                    Err(e) => Err(MyError::ArgonError(e)),
                }
            })
        });

        // Wait for all tasks to complete and collect the results
        let results: Result<Vec<Result<String, MyError>>, tokio::task::JoinError> =
            futures::future::try_join_all(tasks).await;

        match results {
            Ok(hashes) => {
                // Assert that each hashed password is not an error
                for hash in hashes {
                    assert!(hash.is_ok());
                }
            }
            Err(err) => {
                panic!("Failed to hash passwords: {}", err);
            }
        }
    }

    #[test]
    fn test_hash_password_consistency() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let password = "TestPassword";
            let salt = SaltString::generate(&mut OsRng);

            let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
                .map_err(|e| MyError::ArgonError(e.into()))
                .unwrap();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let hash1 = argon2.hash_password(password.as_bytes(), &salt).unwrap();
            let hash2 = argon2.hash_password(password.as_bytes(), &salt).unwrap();

            assert_eq!(hash1, hash2);
        });
    }

    #[test]
    fn test_unique_salts() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let passwords: Vec<&str> = vec!["Password1", "Password2", "Password3"];

            let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
                .map_err(|e| MyError::ArgonError(e.into()))
                .unwrap();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut salts = HashSet::new();
            for password in passwords {
                let salt = SaltString::generate(&mut OsRng);
                assert!(salts.insert(salt.to_string()), "Duplicate salt generated");
                let _ = argon2.hash_password(password.as_bytes(), &salt).unwrap();
            }
        });
    }
    #[test]
    fn test_different_password_lengths() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let binding = "a".repeat(1000);
            let passwords: Vec<&str> = vec!["a", "password123", binding.as_str()];

            // Define Argon2 parameters
            let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
                .map_err(|e| MyError::ArgonError(e.into()))
                .unwrap();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            passwords.into_iter().for_each(|password| {
                let salt = SaltString::generate(&mut OsRng);
                let _ = argon2.hash_password(password.as_bytes(), &salt).unwrap();
            });
        });
    }
    #[test]
    fn test_different_characters_in_passwords() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let passwords: Vec<&str> = vec!["abc123", "P@ssw0rd!", "üñîqúè"];

            // Define Argon2 parameters
            let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
                .map_err(|e| MyError::ArgonError(e.into()))
                .unwrap();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            passwords.into_iter().for_each(|password| {
                let salt = SaltString::generate(&mut OsRng);
                let _ = argon2.hash_password(password.as_bytes(), &salt).unwrap();
            });
        });
    }
}
