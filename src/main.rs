macro_rules! log {
    ($msg:expr) => {
        println!("[LOG] {}", $msg);
    };
}

macro_rules! error {
    ($msg:expr) => {
        println!("[ERROR] {}", $msg);
    };
}

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use std::io::{self, Write};

fn main() {
    let mut password = String::new();
    print!("Please enter your password: ");
    io::stdout().flush().unwrap(); // flush it to the screen

    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim().as_bytes();
    if password.is_empty() {
        error!("You have to provide a password!");
        return;
    }

    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2i,
        argon2::Version::V0x13,
        argon2::Params::new(15000, 2, 1, None).unwrap(),
    );

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password, salt.as_salt()).unwrap();
    log!("Password hashed successfully");
    println!("[LOG] Generated hash: {}", password_hash);

    // Verify password against PHC string.
    let binding = password_hash.to_string();
    let parsed_hash = match PasswordHash::new(&binding) {
        Ok(hash) => {
            log!("Hash parsed successfully");
            hash
        }
        Err(err) => {
            eprintln!("Error parsing hash: {:?}", err);
            return;
        }
    };

    assert!(argon2.verify_password(password, &parsed_hash).is_ok());
    log!("Password verified successfully");
}
