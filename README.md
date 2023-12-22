# Password Hashing in Rust using Argon2
This repository features an implementation of password hashing in Rust using the Argon2 algorithm. For those who are not familiar with this topic, password hashing is a way of securing user passwords by transforming them into a different format, which is then stored instead of the original password.

### Keep in mind that this is a basic implementation and will most likely get updates every once in a while to maintain its performance and readability.

## Argon2

Argon2 is a modern password hashing algorithm that won the [Password Hashing Competition](https://www.password-hashing.net/) in 2015. It is designed to be resistant against brute-force and side-channel attacks by requiring a large amount of memory and time to compute the hash.

## Security and trade-offs of all 3 Argon2 variants
Argon2 has three variants: Argon2d, Argon2i and Argon2id. The main differences between them are:


| Variant | Resistance to GPU Cracking Attacks | Resistance to Side-Channel Attacks |
|---------|-----------------------------------|------------------------------------|
| Argon2d | High                              | Low                                |
| Argon2i | Low                               | High                               |
| Argon2id| Medium                            | Medium                             |


In general, Argon2id is recommended as the default choice for most applications. However, depending on your specific use case and security requirements, you may want to choose a different variant or adjust the parameters of the algorithm, such as the memory size, the number of iterations, and the degree of parallelism.

## Understanding the Attacks

Let's understand what the mentioned attacks actually are:

- A **Cache-Timing Attack** is a type of side-channel attack where an attacker gains information about a system by tracking cache access made by the victim system in a shared environment. 

- A **Side-Channel Attack** is based on the fact that when cryptosystems operate, they cause physical effects, and the information from these effects can provide clues about the system. 

- A **GPU-Based Attack** exploits the graphics processing unit (GPU) of a system.

Because I highly value your security and ask you to be **ABSOLUTELY CAUTIOUS** when using someone else's code, software etc. here are sources to refer to about how to protect yourself from the above mentioned attacks:

[Source related to Cache-Timing Attacks](https://link.springer.com/article/10.1007/s13389-020-00246-3)

[Source related to Side-Channel Attacks](https://techgenix.com/side-channel-attack/)

[Source related to GPU-Based Attacks](https://marksilberstein.com/wp-content/uploads/2020/02/gpuattack.pdf)

## How to run the code?

1. Note: **If you already have rust installed, skip this step**

Here are the necessary steps to get the Rust Compiler for the different Operating Systems Windows, MacOS or Linux:
## Keep in mind that this may change in the future!

  **Windows**:
  1. Install Visual Studio (recommended) or the Microsoft C++ Build Tools.
  2. Install Rust from the Rust website. The website detects that you're running Windows, and it offers you 64- and 32-bit installers of the rustup tool for Windows.
  3. Install the Microsoft C and C++ (MSVC) toolchain by running `rustup default stable-msvc`.

  **MacOS**:
  1. Open a terminal and enter the following command: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`.
  2. Install a C compiler by running: `xcode-select --install`.
  
  **Linux**:
  1. Download the installation script with the curl command and run it in the terminal: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`.
  2. Write your Rust program in a file with a `.rs` extension.

To actually run the code, 

1. **Clone the Repository**: First, you need to clone the repository to your local machine. You can do this using Git with the following command:
   ```shell
   git clone https://github.com/LunaTheFox20/rust-password-hashing.git
   ```

2. **Navigate to the Project Directory**: Use the `cd` (`chdir` if you use Linux or MacOS) command to navigate to the directory containing the project files:
- Windows:
  
   ```shell
   cd rust-password-hashing
   ```
  
 - MacOS & Linux 
   ```shell
   chdir rust-password-hashing
   ```

4. **Build the Project**: Use the Rust package manager, Cargo, to build the project. This will compile your code and create an executable file. Run the following command:
   ```shell
   cargo build --release
   ```
   The `--release` flag will build the project in release mode, with optimizations for performance.

5. **Run the Program**: Finally, you can run the program using Cargo with the following command:
   ```bash
   cargo run --release
   ```
   The program will prompt you to enter the password you want to hash using Argon2.

6. After you entered the password that you want to hash, the program will return the generated hash and verifies the hash to ensure its legitimacy.
