#![feature(test)]
extern crate test;

macro_rules! log {
    ($msg:expr) => {
        println!("[LOG] {}", $msg);
    };
}

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use rand_core::OsRng;
use test::Bencher;

#[bench]
fn bench_password_hashing(b: &mut Bencher) {
    b.iter(|| {
        let password = b"thepasswordgoeshere";
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
    });
}
