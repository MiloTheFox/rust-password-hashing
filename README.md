# 🔐 Password Hashing in Rust using Argon2

This repository demonstrates a **secure implementation of password hashing** in Rust using the [Argon2id](https://www.password-hashing.net/) algorithm.

Password hashing is essential for protecting user credentials: instead of storing raw passwords, we (in the best-case scenario) store their *hashes*. When implemented correctly, this makes it significantly harder for attackers to recover the original passwords.

📖 For background reading:

* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [What Salting has to do with Password Security](https://voleer.com/blog/what-salting-has-to-do-with-password-security)
* [Hashing vs. Salting explained](https://www.tokenex.com/blog/ab-hashing-vs-salting-how-do-these-functions-work/)

---

## ⚡ Argon2

Argon2 is a modern memory-hard password hashing algorithm and winner of the [Password Hashing Competition (PHC)](https://www.password-hashing.net/) in 2015. It is designed to resist:

* **Brute-force attacks** by requiring substantial memory and computation.
* **GPU/ASIC cracking** by being memory-hard.
* **Side-channel attacks** (depending on variant).

### Variants

| Variant      | Resistance to GPU Attacks | Resistance to Side-Channel Attacks | Notes                               |
| ------------ | ------------------------- | ---------------------------------- | ----------------------------------- |
| **Argon2d**  | High                      | Low                                | Focuses on GPU resistance.          |
| **Argon2i**  | Low                       | High                               | Focuses on side-channel resistance. |
| **Argon2id** | Good balance              | Good balance                       | ✔️ Recommended default.             |

---

## ⚠️ Security Considerations

Always adapt Argon2 parameters to your environment and threat model:

* **Memory cost:** Higher values increase GPU/ASIC resistance.
* **Time cost:** Higher values increase CPU effort per hash.
* **Parallelism:** Tune to available cores.

For guidance, see:

* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

More about potential attack vectors:

* [Cache-Timing Attacks](https://link.springer.com/article/10.1007/s13389-020-00246-3)
* [Side-Channel Attacks](https://techgenix.com/side-channel-attack/)
* [GPU-Based Attacks](https://marksilberstein.com/wp-content/uploads/2020/02/gpuattack.pdf)

---

## 🛠️ Installation

### 1. Install Rust

If you don’t already have Rust installed:

* **Windows**

  1. Install Visual Studio (recommended) or Microsoft C++ Build Tools.
  2. Install Rust from [rustup.rs](https://rustup.rs/).
  3. Install the MSVC toolchain:

     ```bash
     rustup default stable-msvc
     ```

* **macOS**

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  xcode-select --install
  ```

* **Linux**

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

### 2. Clone the Repository

```bash
git clone https://github.com/MiloTheFox/rust-password-hashing.git
cd rust-password-hashing
```

### 3. Build the Project

```bash
cargo build --release
```

### 4. Run the Program

```bash
cargo run --release
```

---

## ▶️ Example Output

```text
Generated password: 4Jq^p9As!dF2 (score: 82.3)
Hash output: $argon2id$v=19$m=262144,t=4,p=4$Qm4X1c2...$T+N4J7...
[LOG] All passwords have been hashed successfully
```

By default, the program:

* Generates **20 passwords**.
* Each password has length **16**.
* You can adjust these in `main.rs` via:

  ```rust
  const PASSWORD_COUNT: usize = 20;
  const PASSWORD_LENGTH: usize = 16;
  ```

---

## 📦 Dependencies

This project uses the following crates:

```toml
argon2       = "0.5.3"
rand_core    = { version = "0.6.4", features = ["getrandom"] }
colored      = "2.1.0"
zeroize      = "1.7.0"
futures      = "0.3.30"
passwords    = { version = "3.1.16", features = ["common-password"] }
lazy_static  = "1.4.0"
rayon        = "1.10.0"
log          = "0.4.21"
thiserror    = "1.0.58"
rand         = "0.9.0-alpha.1"
```

All dependencies are installed automatically via Cargo.

---

## 📊 Benchmarking Argon2 Parameters

Hashing cost depends heavily on your hardware. To tune parameters (`MEMORY_COST`, `TIME_COST`, `PARALLELISM`) for your system, you can measure execution time:

```rust
use argon2::{Argon2, Algorithm, Params, Version, password_hash::{SaltString, PasswordHasher}};
use rand_core::OsRng;
use std::time::Instant;

fn main() {
    let params = Params::new(256 * 1024, 4, 4, Some(32)).unwrap(); // 256 MiB, t=4, p=4
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt = SaltString::generate(&mut OsRng);
    let password = "benchmark-password";

    let start = Instant::now();
    let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
    let elapsed = start.elapsed();

    println!("Hash: {}", hash);
    println!("Elapsed time: {:.2?}", elapsed);
}
```

💡 Aim for around **100–250 ms per hash** on your target machine.

* If it's too fast → increase `TIME_COST` or `MEMORY_COST`.
* If it's too slow → decrease them.

---

## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](https://github.com/MiloTheFox/rust-password-hashing/LICENSE.md) for details.

---

## 🤝 Contributing

Contributions are welcome!

* Open issues for bugs or feature requests.
* Submit PRs for fixes or improvements.
