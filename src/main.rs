use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, ParamsBuilder,
};
use colored::Colorize;
use rand_core::OsRng;
use rpassword::prompt_password;
use zeroize::Zeroize;

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let mut password =
        prompt_password("Please enter your password: ").expect("Failed to read password");
    if password.is_empty() {
        eprintln!("{}", "[ERROR] You have to provide a password!".bold().red());
        return;
    }

    let params = ParamsBuilder::default()
        .m_cost(32767) // Memory cost in KiB
        .t_cost(4) // Number of iterations
        .p_cost(8) // Degree of parallelism
        .output_len(32) // Length of the output hash in bytes
        .build()
        .expect("Failed to build params");

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    let salt_clone = salt.clone(); // Clone the salt outside of the closure

    let password_hash = {
        let password_clone = password.clone(); // Clone the password
        argon2
            .hash_password(password_clone.as_bytes(), &salt_clone) // Use the cloned variables
            .expect("Failed to hash password")
    };

    println!("{}", "[LOG] Password hashed successfully".green());
    println!("{} {}", "[LOG] Generated hash: ".yellow(), password_hash);

    let verify_result = {
        let password_clone = password.clone(); // Clone the password
        let argon2_clone = argon2.clone(); // Clone argon2
        tokio::task::spawn_blocking(move || {
            argon2_clone.verify_password(password_clone.as_bytes(), &password_hash) // Use the cloned password and argon2
        })
        .await
        .unwrap()
    };

    if verify_result.is_ok() {
        password.zeroize();
        eprintln!("{}", "[LOG] Password verified successfully".green());
    } else {
        password.zeroize();
        eprintln!("{}", "[ERROR] Password verification failed".bold().red());
    }
}