// SPDX-License-Identifier: Apache-2.0

//! origin-crypto CLI — unified command-line interface for the SDK.
//!
//! # Installation
//! ```bash
//! cargo install origin-crypto-sdk
//! # or
//! cargo build --release --bin origin-crypto && cp target/release/origin-crypto /usr/local/bin/
//! ```
//!
//! # Usage
//! ```bash
//! origin-crypto sign --help
//! origin-crypto verify --help
//! origin-crypto encrypt --help
//! origin-crypto derive --help
//! origin-crypto seed --help
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use origin_crypto_sdk::{
    fill_random, kdf::Argon2idBuilder, prelude::*, seed::derive_child_seed,
    signing::hybrid::Ed25519Falcon1024,
};
use std::fs;
use std::path::PathBuf;

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "origin-crypto",
    version,
    about = "Origin Crypto SDK — hybrid classical/post-quantum cryptography",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hybrid signing (Ed25519 + Falcon-1024)
    Sign(SignArgs),
    /// Verify hybrid signature
    Verify(VerifyArgs),
    /// File encryption with XChaCha20-Poly1305
    Encrypt(EncryptArgs),
    /// File decryption with XChaCha20-Poly1305
    Decrypt(DecryptArgs),
    /// Key derivation (Argon2id)
    Derive(DeriveArgs),
    /// Seed operations
    Seed(SeedArgs),
    /// Show version
    Version,
}

#[derive(Parser)]
struct SignArgs {
    /// Message to sign (or @file to read from file)
    #[arg(short, long)]
    message: String,
    /// Seed hex (32 bytes) or @file
    #[arg(short, long)]
    seed: String,
    /// Domain label for key derivation
    #[arg(short, long, default_value = "zti:hybrid:v1")]
    domain: String,
    /// Output format: json, hex
    #[arg(short, long, default_value = "json")]
    output: OutputFormat,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Message to verify
    #[arg(short, long)]
    message: String,
    /// Signature (JSON with ed25519/falcon1024 hex fields, or @file)
    #[arg(short, long)]
    signature: String,
    /// Seed hex (32 bytes) or @file
    #[arg(short, long)]
    seed: String,
    /// Domain label for key derivation
    #[arg(short, long, default_value = "zti:hybrid:v1")]
    domain: String,
}

#[derive(Parser)]
struct EncryptArgs {
    /// Input file
    #[arg(short, long)]
    input: PathBuf,
    /// Output file
    #[arg(short, long)]
    output: PathBuf,
    /// Key hex (32 bytes) or @file
    #[arg(short, long)]
    key: String,
}

#[derive(Parser)]
struct DecryptArgs {
    /// Input file
    #[arg(short, long)]
    input: PathBuf,
    /// Output file
    #[arg(short, long)]
    output: PathBuf,
    /// Key hex (32 bytes) or @file
    #[arg(short, long)]
    key: String,
}

#[derive(Parser)]
struct DeriveArgs {
    /// Password or @file
    #[arg(short, long)]
    password: String,
    /// Salt hex (16 bytes) or @file, or "generate"
    #[arg(short, long, default_value = "generate")]
    salt: String,
    /// Output key length in bytes
    #[arg(short, long, default_value = "32")]
    length: usize,
    /// Argon2id memory (KiB)
    #[arg(long, default_value = "65536")]
    memory: u32,
    /// Argon2id iterations
    #[arg(long, default_value = "4")]
    iterations: u32,
    /// Argon2id parallelism
    #[arg(long, default_value = "1")]
    parallelism: u32,
}

#[derive(Parser)]
struct SeedArgs {
    #[command(subcommand)]
    action: SeedAction,
}

#[derive(Subcommand)]
enum SeedAction {
    /// Generate new master seed
    Generate {
        /// Entropy source: os, @file
        #[arg(short, long, default_value = "os")]
        entropy: String,
    },
    /// Derive child seed
    Derive {
        /// Master seed hex (32 bytes) or @file
        #[arg(short, long)]
        seed: String,
        /// Domain string
        #[arg(short, long)]
        domain: String,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Json,
    Hex,
}

fn main() -> CliResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            println!("origin-crypto {}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Sign(args) => cmd_sign(args)?,
        Commands::Verify(args) => cmd_verify(args)?,
        Commands::Encrypt(args) => cmd_encrypt(args)?,
        Commands::Decrypt(args) => cmd_decrypt(args)?,
        Commands::Derive(args) => cmd_derive(args)?,
        Commands::Seed(args) => cmd_seed(args)?,
    }
    Ok(())
}

fn read_input(s: &str) -> CliResult<Vec<u8>> {
    if s.starts_with('@') {
        Ok(fs::read(&s[1..])?)
    } else {
        Ok(hex::decode(s)?)
    }
}

fn read_string_input(s: &str) -> CliResult<String> {
    if s.starts_with('@') {
        Ok(fs::read_to_string(&s[1..])?)
    } else {
        Ok(s.to_string())
    }
}

fn to_array_32(bytes: Vec<u8>) -> CliResult<[u8; 32]> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "expected 32 bytes (64 hex chars)".into())
}

fn to_array_16(bytes: Vec<u8>) -> CliResult<[u8; 16]> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "expected 16 bytes (32 hex chars)".into())
}

fn cmd_sign(args: SignArgs) -> CliResult<()> {
    let msg = read_string_input(&args.message)?;
    let seed = to_array_32(read_input(&args.seed)?)?;

    let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
        .map_err(|e| format!("bundle: {}", e))?;
    let sig = bundle.sign_hybrid(msg.as_bytes());

    match args.output {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
                "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
                "domain": args.domain,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        OutputFormat::Hex => {
            let mut out = Vec::new();
            out.extend_from_slice(sig.ed25519_sig.to_bytes().as_ref());
            out.extend_from_slice(sig.falcon_sig.as_bytes());
            println!("{}", hex::encode(out));
        }
    }
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> CliResult<()> {
    let msg = read_string_input(&args.message)?;
    let seed = to_array_32(read_input(&args.seed)?)?;

    let sig_json = read_string_input(&args.signature)?;
    let sig_val: serde_json::Value = serde_json::from_str(&sig_json)?;
    let ed25519_hex = sig_val["ed25519"].as_str().ok_or("missing ed25519 field")?;
    let falcon_hex = sig_val["falcon1024"]
        .as_str()
        .ok_or("missing falcon1024 field")?;

    let ed_sig_bytes = hex::decode(ed25519_hex)?;
    let falcon_sig_bytes = hex::decode(falcon_hex)?;

    let ed_sig = ed25519_dalek::Signature::from_bytes(
        ed_sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "ed25519 sig must be 64 bytes")?,
    );
    let falcon_sig =
        origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&falcon_sig_bytes)
            .map_err(|e| format!("falcon sig: {}", e))?;

    let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
        .map_err(|e| format!("bundle: {}", e))?;
    let combined = Ed25519Falcon1024 {
        ed25519_sig: ed_sig,
        falcon_sig,
    };
    Ed25519Falcon1024::verify(
        bundle.ed25519_pk(),
        bundle.falcon1024_pk(),
        msg.as_bytes(),
        &combined,
    )
    .map_err(|e| format!("verify: {}", e))?;

    println!("valid");
    Ok(())
}

fn cmd_encrypt(args: EncryptArgs) -> CliResult<()> {
    let data = fs::read(&args.input)?;
    let key = to_array_32(read_input(&args.key)?)?;

    let mut nonce = [0u8; 24];
    fill_random(&mut nonce)?;
    let ct =
        XChaCha20Poly1305::encrypt(&key, &nonce, &data).map_err(|e| format!("encrypt: {}", e))?;
    let ct_len = ct.len();
    let mut out = Vec::with_capacity(24 + ct_len);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    fs::write(&args.output, out)?;
    println!(
        "encrypted {} -> {} ({} bytes)",
        args.input.display(),
        args.output.display(),
        ct_len
    );
    Ok(())
}

fn cmd_decrypt(args: DecryptArgs) -> CliResult<()> {
    let data = fs::read(&args.input)?;
    if data.len() < 24 {
        return Err("file too short for nonce".into());
    }
    let key = to_array_32(read_input(&args.key)?)?;

    let nonce: [u8; 24] = data[..24].try_into().unwrap();
    let ct = &data[24..];

    let pt = XChaCha20Poly1305::decrypt(&key, &nonce, ct).map_err(|e| format!("decrypt: {}", e))?;
    // Borrow `pt` rather than move so the trailing `pt.len()` status print compiles.
    fs::write(&args.output, &pt)?;
    println!(
        "decrypted {} -> {} ({} bytes)",
        args.input.display(),
        args.output.display(),
        pt.len()
    );
    Ok(())
}

fn cmd_derive(args: DeriveArgs) -> CliResult<()> {
    let password = read_string_input(&args.password)?;
    let salt = if args.salt == "generate" {
        let mut s = [0u8; 16];
        fill_random(&mut s)?;
        s
    } else {
        to_array_16(read_input(&args.salt)?)?
    };

    let builder = Argon2idBuilder::new()
        .memory_kib(args.memory)
        .iterations(args.iterations)
        .parallelism(args.parallelism)
        .output_len(args.length);
    let out = builder
        .derive(password.as_bytes(), &salt)
        .map_err(|e| format!("derive: {}", e))?;

    println!("salt: {}", hex::encode(&salt));
    println!("key:  {}", hex::encode(&out));
    Ok(())
}

fn cmd_seed(args: SeedArgs) -> CliResult<()> {
    match args.action {
        SeedAction::Generate { entropy } => {
            let mut seed = [0u8; 32];
            match entropy.as_str() {
                "os" | "system" => {
                    fill_random(&mut seed)?;
                }
                _ if entropy.starts_with('@') => {
                    let data = fs::read(&entropy[1..])?;
                    seed.copy_from_slice(&data[..32.min(data.len())]);
                }
                _ => return Err("unknown entropy source".into()),
            }
            println!("{}", hex::encode(seed));
        }
        SeedAction::Derive { seed, domain } => {
            let seed = to_array_32(read_input(&seed)?)?;
            let child =
                derive_child_seed(&seed, &domain).map_err(|e| format!("derive child: {}", e))?;
            println!("{}", hex::encode(child));
        }
    }
    Ok(())
}
