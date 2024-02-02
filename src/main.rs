use argon2::{
   password_hash::{PasswordHasher, PasswordVerifier, SaltString},
   Algorithm, Argon2, Params, Version,
};
use colored::Colorize;
use rand_core::OsRng;
use rayon::prelude::*; // import rayon prelude
use zeroize::Zeroizing;
use log::{info, warn};

const MEMORY_COST: u32 = 65534;
const TIME_COST: u32 = 8;
const PARALLELISM: u32 = 16;
const OUTPUT_LEN: usize = 64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
   // Generate a single salt for all password hashes
   let salt = SaltString::generate(&mut OsRng);

   // Create a vector of passwords to hash
   let passwords = Zeroizing::new(vec![
       "YourFirstPassword",
       "YourSecondPassword",
       "Eeeee",
       "4thPassword",
       // etc.
   ]);

   let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))?;
   let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)?;

   // Use rayon to hash the passwords in parallel
   let hashes: Vec<_> = passwords
       .into_par_iter()
       .map(|password| argon2.hash_password(password.as_bytes(), &salt))
       .collect_into_vec();

   // Log the generated hashes (outside the parallel loop)
   for hash in &hashes {
       info!("{} {:?}", "[LOG] Generated hash: ".yellow(), hash?);
   }

   info!("{}", "[LOG] Passwords hashed successfully".green());
   Ok(())
}