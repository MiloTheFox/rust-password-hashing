use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, ParamsBuilder,
};
use colored::Colorize;
use rand_core::OsRng;
use rpassword::prompt_password;
use zeroize::Zeroize;

fn main() {
    // Prompt the user to enter a password using the rpassword crate, which hides the input from the screen for security reasons.
    let mut password =
        prompt_password("Please enter your password: ").expect("Failed to read password");
    // Check if the password is empty and exit the program if so.
    if password.is_empty() {
        eprintln!("{}", "[ERROR] You have to provide a password!".bold().red());
        return;
    }

    // Specify the parameters for the Argon2 password hashing algorithm, which control the computational cost of hashing to ensure password security.
    let params = ParamsBuilder::default()
        .m_cost(32767) // Memory cost in KiB
        .t_cost(4) // Number of iterations
        .p_cost(8) // Degree of parallelism
        .output_len(32) // Length of the output hash in bytes
        .build()
        .expect("Failed to build params");

    // Generate a random salt string using the OsRng crate. The salt is used to uniquely identify the password hash and protect against attacks that try to guess the password from a list of common hashes.
    let salt = SaltString::generate(&mut OsRng);
    // Create an instance of the Argon2 hasher with the specified parameters.
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Hash the password using the Argon2 hasher and the salt to create a secure representation of the password.
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");

    // Print a success message and the generated hash.
    println!("{}", "[LOG] Password hashed successfully".green());
    println!("{} {}", "[LOG] Generated hash: ".yellow(), password_hash);

    // Verify the password against the hash using the Argon2 verifier to ensure the password is correct.
    if argon2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok()
    {
        // Clear the password from memory using the Zeroize crate to prevent accidental leakage or retrieval of the sensitive password information.
        password.zeroize();
        // Print a success message.
        eprintln!("{}", "[LOG] Password verified successfully".green());
    } else {
        // Clear the password from memory like above.
        password.zeroize();
        // Print an error message.
        eprintln!("{}", "[ERROR] Password verification failed".bold().red());
    }
}
