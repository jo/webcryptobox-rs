use webcryptobox::Webcryptobox;

use std::env;
use std::fs;
use std::io;
use std::io::Read;

fn help() {
    println!("Usage: webcryptobox <command> [arguments]

generate-key-pair
    Generate ECDH key and output private key as pem
generate-key
    Generate AES key, output as hex
generate-iv
    Generate an initialization vector, output as hex
derive-public-key <filename>
    Derive public key from private key PEM file, output public key pem
sha1-fingerprint <filename>
    Calculate SHA-1 fingerprint from private or public key pem file, output hex
sha256-fingerprint <filename>
    Calculate SHA-256 fingerprint from private or public key pem file, output hex
derive-key <private-key-filename> <public-key-filename>
    derive AES key from private and public key files as pem, output hex
encrypt <key> <iv>
    reads message from STDIN and key and iv as hex args,
    encrypts message and prints out as base64
decrypt <key> <iv>
    reads encrypted message in base64 format from STDIN and key and iv as hex args
    prints out decrypted message
derive-and-encrypt <private-key-filename> <public-key-filename> <iv>
    reads message from STDIN and private and public key files as pem and iv as hex
    encrypts message and prints out as base64
derive-and-decrypt <private-key-filename> <public-key-filename> <iv>
    reads encrypted message in base64 format from STDIN, private and public key files as pem and iv as hex
    prints out decrypted message

Cipher can be configured via the following environment variables:
  CURVE:  can be P-521, P-384 or P-256. Defaults to P-521
  MODE:   can be GCM or CBC. Defaults to GCM
  LENGTH: can be 256 or 128. Default is 256");
}

pub fn main() {
    let curve = env::var("CURVE").unwrap_or("P-521".to_string());
    let mode = env::var("MODE").unwrap_or("GCM".to_string());
    let length = env::var("LENGTH").unwrap_or("256".to_string());
    let length = length.parse::<usize>().unwrap();

    let wcb = Webcryptobox::new(&curve, &mode, length);

    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => help(),
        2 => {
            let cmd = &args[1];
            match &cmd[..] {
                "generate-key-pair" => {
                    let key = wcb.generate_key_pair().unwrap();
                    let pem = wcb.export_private_key_pem(key).unwrap();
                    let pem_string = std::str::from_utf8(&pem).unwrap();
                    println!("{}", pem_string)
                }
                "generate-key" => {
                    let key = wcb.generate_key().unwrap();
                    let key_string = hex::encode(key);
                    println!("{}", key_string)
                }
                "generate-iv" => {
                    let key = wcb.generate_iv().unwrap();
                    let key_string = hex::encode(key);
                    println!("{}", key_string)
                }
                _ => help(),
            }
        }
        3 => {
            let cmd = &args[1];
            match &cmd[..] {
                "derive-public-key" => {
                    let filename = &args[2];

                    let pem = fs::read(filename).unwrap();
                    let key = wcb.import_private_key_pem(&pem).unwrap();
                    let public_key = wcb.derive_public_key(&key).unwrap();
                    let pem = wcb.export_public_key_pem(&public_key).unwrap();
                    let pem_string = std::str::from_utf8(&pem).unwrap();
                    println!("{}", pem_string)
                }
                "sha1-fingerprint" => {
                    let filename = &args[2];

                    let pem = fs::read(filename).unwrap();
                    let fingerprint = match pem.starts_with(b"-----BEGIN PRIVATE KEY-----") {
                        true => {
                            let key = wcb.import_private_key_pem(&pem).unwrap();
                            wcb.sha1_fingerprint_from_private_key(&key).unwrap()
                        }
                        _ => {
                            let key = wcb.import_public_key_pem(&pem).unwrap();
                            wcb.sha1_fingerprint_from_public_key(&key).unwrap()
                        }
                    };
                    println!("{}", fingerprint)
                }
                "sha256-fingerprint" => {
                    let filename = &args[2];

                    let pem = fs::read(filename).unwrap();
                    let fingerprint = match pem.starts_with(b"-----BEGIN PRIVATE KEY-----") {
                        true => {
                            let key = wcb.import_private_key_pem(&pem).unwrap();
                            wcb.sha256_fingerprint_from_private_key(&key).unwrap()
                        }
                        _ => {
                            let key = wcb.import_public_key_pem(&pem).unwrap();
                            wcb.sha256_fingerprint_from_public_key(&key).unwrap()
                        }
                    };
                    println!("{}", fingerprint)
                }
                _ => help(),
            }
        }
        4 => {
            let cmd = &args[1];
            match &cmd[..] {
                "derive-key" => {
                    let private_key_filename = &args[2];
                    let public_key_filename = &args[3];

                    let private_key_pem = fs::read(private_key_filename).unwrap();
                    let private_key = wcb.import_private_key_pem(&private_key_pem).unwrap();

                    let public_key_pem = fs::read(public_key_filename).unwrap();
                    let public_key = wcb.import_public_key_pem(&public_key_pem).unwrap();

                    let key = wcb.derive_key(private_key, public_key).unwrap();
                    let key_string = hex::encode(key);
                    println!("{}", key_string)
                }
                "encrypt" => {
                    let key_hex = &args[2];
                    let iv_hex = &args[3];

                    let key = hex::decode(key_hex).unwrap();
                    let iv = hex::decode(iv_hex).unwrap();

                    let mut data = Vec::new();
                    io::stdin().read_to_end(&mut data).unwrap();

                    let encrypted_data = wcb.encrypt(&key, &iv, &data).unwrap();
                    let encrypted_data_base64 = base64::encode(encrypted_data);

                    println!("{}", encrypted_data_base64)
                }
                "decrypt" => {
                    let key_hex = &args[2];
                    let iv_hex = &args[3];

                    let key = hex::decode(key_hex).unwrap();
                    let iv = hex::decode(iv_hex).unwrap();

                    let mut data_base64 = Vec::new();
                    io::stdin().read_to_end(&mut data_base64).unwrap();
                    let data = base64::decode(data_base64).unwrap();

                    let message = wcb.decrypt(&key, &iv, &data).unwrap();
                    let message_string = std::str::from_utf8(&message).unwrap();

                    println!("{}", message_string)
                }
                _ => help(),
            }
        }
        5 => {
            let cmd = &args[1];
            match &cmd[..] {
                "derive-and-encrypt" => {
                    let private_key_filename = &args[2];
                    let public_key_filename = &args[3];
                    let iv_hex = &args[4];

                    let mut data = Vec::new();
                    io::stdin().read_to_end(&mut data).unwrap();

                    let private_key_pem = fs::read(private_key_filename).unwrap();
                    let private_key = wcb.import_private_key_pem(&private_key_pem).unwrap();
                    let public_key_pem = fs::read(public_key_filename).unwrap();
                    let public_key = wcb.import_public_key_pem(&public_key_pem).unwrap();
                    let key = wcb.derive_key(private_key, public_key).unwrap();
                    let iv = hex::decode(iv_hex).unwrap();
                    let encrypted_data = wcb.encrypt(&key, &iv, &data).unwrap();
                    let encrypted_data_base64 = base64::encode(encrypted_data);

                    println!("{}", encrypted_data_base64)
                }
                "derive-and-decrypt" => {
                    let private_key_filename = &args[2];
                    let public_key_filename = &args[3];
                    let iv_hex = &args[4];
                    let mut data_base64 = Vec::new();
                    io::stdin().read_to_end(&mut data_base64).unwrap();

                    let private_key_pem = fs::read(private_key_filename).unwrap();
                    let private_key = wcb.import_private_key_pem(&private_key_pem).unwrap();
                    let public_key_pem = fs::read(public_key_filename).unwrap();
                    let public_key = wcb.import_public_key_pem(&public_key_pem).unwrap();
                    let key = wcb.derive_key(private_key, public_key).unwrap();
                    let iv = hex::decode(iv_hex).unwrap();
                    let data = base64::decode(data_base64).unwrap();
                    let message = wcb.decrypt(&key, &iv, &data).unwrap();
                    let message_string = std::str::from_utf8(&message).unwrap();

                    println!("{}", message_string)
                }
                _ => help(),
            }
        }
        _ => help(),
    }
}
