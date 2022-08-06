use std::{
    io::{stdout, Write},
    process,
};

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use clap::Parser;
use dryoc::{
    classic::crypto_generichash::crypto_generichash,
    keypair::{KeyPair, PublicKey},
};
use tiny_hderive::bip32::ExtendedPrivKey;

const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Find a mnemonic phrase for a Tezos address starting with the specified "tz1<TERM>".
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Search term
    #[clap(short, long)]
    term: String,
}

fn main() {
    let cli = Cli::parse();

    // Validate search term
    for char in cli.term.chars() {
        if !ALPHABET.contains(char) {
            eprintln!("Search term is invalid. Use only base58 symbols.");
            process::exit(1);
        }
    }
    let term = format!("tz1{}", cli.term);
    println!("Searching for {}", term);
    println!(
        "Est. {} addresses need to be checked.",
        58usize.pow((term.len() - 3).try_into().unwrap()) / 2
    );

    // Initialize counter
    let mut count = 0;
    print!("Checked 0 addresses");
    stdout().flush().unwrap();

    loop {
        // Derive address from a fresh mnemonic
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let seed = Seed::new(&mnemonic, "");
        let ext = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/1729'/0'/0'").unwrap();
        let public_key: PublicKey = KeyPair::from_secret_key(ext.secret()).public_key;
        let mut public_key_hash = {
            let mut pkh = [0u8; 20];
            crypto_generichash(&mut pkh, &public_key, None).unwrap();
            pkh.to_vec()
        };
        let address = {
            let mut address: Vec<u8> = vec![6, 161, 159];
            address.append(&mut public_key_hash);
            bs58::encode(address).with_check().into_string()
        };

        // Increment counter
        count += 1;
        print!("\rChecked {} addresses", count);
        stdout().flush().unwrap();

        // Check address against search term
        if address.starts_with(&term) {
            println!();
            println!("Found match:");
            println!("{}", address);
            println!("{}", mnemonic);
            break;
        }
    }
}
