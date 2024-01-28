use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, ParamsBuilder,
};
use colored::Colorize;
use rand_core::OsRng;
use rpassword::prompt_password;
use zeroize::Zeroize;

fn main() {
    let mut password =
        prompt_password("Please enter your password: ").expect("Failed to read password");
    if password.is_empty() {
        eprintln!("{}", "[ERROR] You have to provide a password!".bold().red());
        return;
    }

    let params = ParamsBuilder::default()
        .m_cost(32767)
        .t_cost(4)
        .p_cost(8)
        .output_len(32)
        .build()
        .expect("Failed to build params");

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");

    eprintln!("{}", "[LOG] Password hashed successfully".green());
    println!("{} {}", "[LOG] Generated hash: ".yellow(), password_hash);

    if argon2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok()
    {
        password.zeroize();
        eprintln!("{}", "[LOG] Password verified successfully".green());
    } else {
        password.zeroize();
        eprintln!("{}", "[ERROR] Password verification failed".bold().red());
    }
}
