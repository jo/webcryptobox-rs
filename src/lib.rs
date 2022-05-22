#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

//! Webcryptobox provides convenient wrappers around
//! [OpenSSL](https://docs.rs/openssl/latest/openssl/) to use
//! [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) compatible
//! cryptography.
//!
//! It works nicely together with the [JavaScript
//! Webcryptobox](https://github.com/jo/webcryptobox-js) and [Bash
//! Webcryptobox](https://github.com/jo/webcryptobox-sh).
//!
//! Webcryptobox helps with elliptic curve key generation, derivation, fingerprinting, import and
//! export as well as AES encryption and decryption.
//!
//! # Example:
//!
//! ```rust
//! // Alice creates a key and sends her public key pem to Bob
//! let alice = webcryptobox::generate_private_key().unwrap();
//! let alice_public_key = webcryptobox::get_public_key(&alice).unwrap();
//! let alice_public_key_pem = webcryptobox::export_public_key_pem(&alice_public_key).unwrap();
//!
//! // Bob also creates a key and sends his public key pem to Alice
//! let bob = webcryptobox::generate_private_key().unwrap();
//! let bobs_public_key = webcryptobox::get_public_key(&bob).unwrap();
//! let bob_public_key_pem = webcryptobox::export_public_key_pem(&bobs_public_key).unwrap();
//!
//! // Alice uses Bobs public key to derive a shared key
//! let bobs_key = webcryptobox::import_public_key_pem(&bob_public_key_pem).unwrap();
//! let alice_shared_key = webcryptobox::derive_key(alice, bobs_key).unwrap();
//!
//! // She now encrypts a message and sends the encrypted message and the iv to Bob
//! let data = (b"a secret message").to_vec();
//! let encrypted_message = webcryptobox::encrypt(&alice_shared_key, &data).unwrap();
//!
//! // Now Bob derives the same shared secret
//! let alice_key = webcryptobox::import_public_key_pem(&alice_public_key_pem).unwrap();
//! let bobs_shared_key = webcryptobox::derive_key(bob, alice_key).unwrap();
//!
//! // and decrypts the message
//! let message = webcryptobox::decrypt(&bobs_shared_key, &encrypted_message);
//! ```

use openssl::derive::Deriver;
use openssl::ec::EcGroup;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha;
use openssl::symm;

// re-exports
pub use openssl::ec::EcKey;
pub use openssl::pkey::{Private, Public};

// Cipher configuration
const CURVE: Nid = Nid::SECP521R1;
const CIPHER: fn() -> symm::Cipher = symm::Cipher::aes_256_cbc;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const PASSPHRASE_LENGTH: usize = 32;

fn get_group() -> EcGroup {
    EcGroup::from_curve_name(CURVE).unwrap()
}

fn get_cipher() -> symm::Cipher {
    CIPHER()
}

/// Generate an EC private key.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key();
/// ```
pub fn generate_private_key() -> Result<EcKey<Private>, ErrorStack> {
    let group = get_group();
    EcKey::generate(&group)
}

/// Given a private EC key, derives the public EC key.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let public_key = webcryptobox::get_public_key(&key);
/// ```
pub fn get_public_key(private_key: &EcKey<Private>) -> Result<EcKey<Public>, ErrorStack> {
    let group = get_group();
    let key_point = private_key.public_key();

    EcKey::from_public_key(&group, &key_point)
}

/// Export a private EC key in PEM format.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let pem = webcryptobox::export_private_key_pem(key);
/// ```
pub fn export_private_key_pem(private_key: EcKey<Private>) -> Result<Vec<u8>, ErrorStack> {
    let key = PKey::from_ec_key(private_key).unwrap();
    key.private_key_to_pem_pkcs8()
}

/// Import a private key PEM.
///
/// # Example:
///
/// ```rust
/// let pem = (b"-----BEGIN PRIVATE KEY-----
/// MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBcf8zEjlssqn4aTEB
/// RR43ofwH/4BAXDAAd83Kz1Dyd+Ko0pit4ESgqSu/bJMdnDrpiGYuz0Klarwip8LD
/// rYd9mEahgYkDgYYABAF2Nu9XKPs2CVFocuqCfaX5FzDUt6/nT/3Evqq8jBhK/ziN
/// TrEs4wkZjuei5TS25aabX6iMex3etoN/GOw1KYpI4QBtIUnWudG8FT8N+USHSL9G
/// h9fi+Yofeq4Io9DxPU1ChCKPIoQ6ORAMWoOCk9bTdIy6yqx33+RIM04wub4QAgDo
/// LQ==
/// -----END PRIVATE KEY-----").to_vec();
/// let key = webcryptobox::import_private_key_pem(&pem);
/// ```
pub fn import_private_key_pem(pem: &[u8]) -> Result<EcKey<Private>, ErrorStack> {
    EcKey::private_key_from_pem(pem)
}

/// Export a encrypted private EC key in PEM format.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let passphrase = b"secret passphrase";
/// let pem = webcryptobox::export_encrypted_private_key_pem(key, passphrase);
/// ```
pub fn export_encrypted_private_key_pem(
    private_key: EcKey<Private>,
    passphrase: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let cipher = get_cipher();
    let key = PKey::from_ec_key(private_key).unwrap();
    key.private_key_to_pem_pkcs8_passphrase(cipher, passphrase)
}

/// Import an encrypted private key PEM.
///
/// # Example:
///
/// ```rust
/// let pem = (b"-----BEGIN ENCRYPTED PRIVATE KEY-----
/// MIIBZjBgBgkqhkiG9w0BBQ0wUzAyBgkqhkiG9w0BBQwwJQQQOG0vrzwWTXnZGV40
/// QTUa7gIDAPoAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBChJ598h/deO6WH
/// YdP1lue+BIIBAE9tqarEYD51VXFCPsbIT/CVaF7RJ4emUNvk29Q35hNcf+2CRCki
/// K8T23KAPQ7GFkHBdmykV2uNvZ+CWCeKeOqj9AZU36mHK4gkIQz1bgADRjRp/lb2j
/// mBvg7Yzm3+H67zRmkr44jdqc8BJFCeqaMH6Fm6XQR0IPtUhmrR8YZyc1ka9L5+IB
/// Qk+SWDXF0brMnpLiwdKPABb4qCJ49qNwR0xVGlYyAv/XdT5PkyzzZxpwv2hLv7zw
/// y9KnnZ4qA0ceNo4RBYuWALlfqWANARl8lAvHLdSedN7cW9lU2PyXB+70twInt4Ty
/// lkyFWM+JH9SavLEAdG1mPHnYJB1INSMifS0=
/// -----END ENCRYPTED PRIVATE KEY-----").to_vec();
/// let passphrase = b"secret passphrase";
/// let key = webcryptobox::import_encrypted_private_key_pem(&pem, passphrase);
/// ```
pub fn import_encrypted_private_key_pem(
    pem: &[u8],
    passphrase: &[u8],
) -> Result<EcKey<Private>, ErrorStack> {
    EcKey::private_key_from_pem_passphrase(pem, passphrase)
}

/// Export a encrypted private EC key in PEM format with key pair
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let alice = webcryptobox::generate_private_key().unwrap();
/// let alice_public_key = webcryptobox::get_public_key(&alice).unwrap();
/// webcryptobox::export_encrypted_private_key_pem_to(key, alice, alice_public_key).unwrap();
/// ```
pub fn export_encrypted_private_key_pem_to(
    key: EcKey<Private>,
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
) -> Result<Vec<u8>, ErrorStack> {
    let cipher = get_cipher();
    let pkey = PKey::from_ec_key(key).unwrap();
    let bits = derive_password(private_key, public_key, &PASSPHRASE_LENGTH).unwrap();
    let passphrase = hex::encode(bits);
    let passphrase_bits = passphrase.as_bytes();
    pkey.private_key_to_pem_pkcs8_passphrase(cipher, &passphrase_bits)
}

/// Import an encrypted private key PEM from key pair.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let alice = webcryptobox::generate_private_key().unwrap();
/// let alice_public_key = webcryptobox::get_public_key(&alice).unwrap();
/// let bob = webcryptobox::generate_private_key().unwrap();
/// let bob_public_key = webcryptobox::get_public_key(&bob).unwrap();
/// let pem = webcryptobox::export_encrypted_private_key_pem_to(key, alice, bob_public_key).unwrap();
/// webcryptobox::import_encrypted_private_key_pem_from(&pem, bob, alice_public_key).unwrap();
/// ```
pub fn import_encrypted_private_key_pem_from(
    pem: &[u8],
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
) -> Result<EcKey<Private>, ErrorStack> {
    let bits = derive_password(private_key, public_key, &PASSPHRASE_LENGTH).unwrap();
    let passphrase = hex::encode(bits);
    let passphrase_bits = passphrase.as_bytes();
    EcKey::private_key_from_pem_passphrase(pem, &passphrase_bits)
}

/// Export a public EC key in PEM format.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let public_key = webcryptobox::get_public_key(&key).unwrap();
/// let pem = webcryptobox::export_public_key_pem(&public_key);
/// ```
pub fn export_public_key_pem(public_key: &EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
    public_key.public_key_to_pem()
}

/// Import a public key PEM.
///
/// # Example:
///
/// ```rust
/// let pem = (b"-----BEGIN PUBLIC KEY-----
/// MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBdjbvVyj7NglRaHLqgn2l+Rcw1Lev
/// 50/9xL6qvIwYSv84jU6xLOMJGY7nouU0tuWmm1+ojHsd3raDfxjsNSmKSOEAbSFJ
/// 1rnRvBU/DflEh0i/RofX4vmKH3quCKPQ8T1NQoQijyKEOjkQDFqDgpPW03SMusqs
/// d9/kSDNOMLm+EAIA6C0=
/// -----END PUBLIC KEY-----").to_vec();
/// let key = webcryptobox::import_public_key_pem(&pem);
/// ```
pub fn import_public_key_pem(pem: &[u8]) -> Result<EcKey<Public>, ErrorStack> {
    EcKey::public_key_from_pem(pem)
}

/// Calculate a SHA-1 fingeprint from a private key.
///
/// This hashes the DER data of the public key part of the key. Note this does not create a
/// hash of the private key, but the public key.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let fingerprint = webcryptobox::sha1_fingerprint_from_private_key(&key);
/// ```
pub fn sha1_fingerprint_from_private_key(key: &EcKey<Private>) -> Result<Vec<u8>, ErrorStack> {
    let der = key.public_key_to_der().unwrap();
    let mut hasher = sha::Sha1::new();
    hasher.update(&der);
    let hash = hasher.finish();

    Ok(hash.to_vec())
}

/// Calculate a SHA-1 fingeprint of a public key.
///
/// This hashes the DER data of the key.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let public_key = webcryptobox::get_public_key(&key).unwrap();
/// let fingerprint = webcryptobox::sha1_fingerprint_from_public_key(&public_key);
/// ```
pub fn sha1_fingerprint_from_public_key(key: &EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
    let der = key.public_key_to_der().unwrap();
    let mut hasher = sha::Sha1::new();
    hasher.update(&der);
    let hash = hasher.finish();

    Ok(hash.to_vec())
}

/// Calculate a SHA-256 fingeprint from a private key.
///
/// This hashes the DER data of the public key part of the key. Note this does not create a
/// hash of the private key, but the public key.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let fingerprint = webcryptobox::sha256_fingerprint_from_private_key(&key);
/// ```
pub fn sha256_fingerprint_from_private_key(key: &EcKey<Private>) -> Result<Vec<u8>, ErrorStack> {
    let der = key.public_key_to_der().unwrap();
    let mut hasher = sha::Sha256::new();
    hasher.update(&der);
    let hash = hasher.finish();

    Ok(hash.to_vec())
}

/// Calculate a SHA-256 fingeprint of a public key.
///
/// This hashes the DER data of the key.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_private_key().unwrap();
/// let public_key = webcryptobox::get_public_key(&key).unwrap();
/// let fingerprint = webcryptobox::sha256_fingerprint_from_public_key(&public_key);
/// ```
pub fn sha256_fingerprint_from_public_key(key: &EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
    let der = key.public_key_to_der().unwrap();
    let mut hasher = sha::Sha256::new();
    hasher.update(&der);
    let hash = hasher.finish();

    Ok(hash.to_vec())
}

/// Generate AES key material to be used with `encrypt` and `decrypt`.
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_key();
/// ```
pub fn generate_key() -> Result<Vec<u8>, ErrorStack> {
    let mut key = vec![0; KEY_LENGTH];
    rand_bytes(&mut key).unwrap();
    Ok(key)
}

// Derives bits from given private and public key.
fn derive_bits(
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
    length: usize,
) -> Result<Vec<u8>, ErrorStack> {
    let private_key = PKey::from_ec_key(private_key).unwrap();
    let public_key = PKey::from_ec_key(public_key).unwrap();

    let mut deriver = Deriver::new(&private_key).unwrap();
    deriver.set_peer(&public_key).unwrap();

    let mut bits = vec![0; length];
    deriver.derive(&mut bits).unwrap();
    Ok(bits)
}

/// Derives AES key material to be used with `encrypt` and `decrypt` from given private and
/// public key.
///
/// # Example:
///
/// ```rust
/// let alice = webcryptobox::generate_private_key().unwrap();
/// let bob = webcryptobox::generate_private_key().unwrap();
/// let bobs_public_key = webcryptobox::get_public_key(&bob).unwrap();
/// let key = webcryptobox::derive_key(alice, bobs_public_key);
/// ```
pub fn derive_key(
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
) -> Result<Vec<u8>, ErrorStack> {
    derive_bits(private_key, public_key, KEY_LENGTH)
}

/// Derives password bits from given private and public key.
///
/// # Example:
///
/// ```rust
/// let alice = webcryptobox::generate_private_key().unwrap();
/// let bob = webcryptobox::generate_private_key().unwrap();
/// let bobs_public_key = webcryptobox::get_public_key(&bob).unwrap();
/// let password = webcryptobox::derive_password(alice, bobs_public_key, &16);
/// ```
pub fn derive_password(
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
    length: &usize,
) -> Result<Vec<u8>, ErrorStack> {
    let bits = derive_bits(private_key, public_key, length + KEY_LENGTH).unwrap();
    Ok(bits[KEY_LENGTH..].to_vec())
}

// Generate AES initialization vector to be used in `encrypt` and `decrypt`.
fn generate_iv() -> Result<Vec<u8>, ErrorStack> {
    let mut iv = vec![0; IV_LENGTH];
    rand_bytes(&mut iv).unwrap();
    Ok(iv)
}

/// Encrypts data with aes-266-cbc
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_key().unwrap();
/// let data = (b"a secret message").to_vec();
/// let encrypted_message = webcryptobox::encrypt(&key, &data);
/// ```
pub fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = get_cipher();
    let mut iv = generate_iv().unwrap();
    let ciphertext = symm::encrypt(cipher, key, Some(&iv), data).unwrap();
    iv.extend(ciphertext);
    Ok(iv)
}

/// Decrypts aes encrypted data
///
/// # Example:
///
/// ```rust
/// let key = webcryptobox::generate_key().unwrap();
/// let data = (b"a secret message").to_vec();
/// let encrypted_message = webcryptobox::encrypt(&key, &data).unwrap();
///
/// let message = webcryptobox::decrypt(&key, &encrypted_message);
/// ```
pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = get_cipher();
    let iv = &data[0..IV_LENGTH];
    let d = &data[IV_LENGTH..];
    symm::decrypt(cipher, key, Some(iv), &d)
}

/// Derives AES key from given private and public key and encrypts message.
///
/// # Example:
///
/// ```rust
/// let alice = webcryptobox::generate_private_key().unwrap();
/// let bob = webcryptobox::generate_private_key().unwrap();
/// let bobs_public_key = webcryptobox::get_public_key(&bob).unwrap();
///
/// let data = (b"a secret message").to_vec();
/// let encrypted_message = webcryptobox::derive_and_encrypt(alice, bobs_public_key, &data);
/// ```
pub fn derive_and_encrypt(
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let key = derive_key(private_key, public_key).unwrap();

    encrypt(&key, data)
}

/// Derives AES key from given private and public key and decrypts message.
///
/// # Example:
///
/// ```rust
/// let alice = webcryptobox::generate_private_key().unwrap();
/// let bob = webcryptobox::generate_private_key().unwrap();
/// let alice_public_key = webcryptobox::get_public_key(&alice).unwrap();
/// let bobs_public_key = webcryptobox::get_public_key(&bob).unwrap();
///
/// let data = (b"a secret message").to_vec();
/// let encrypted_message = webcryptobox::derive_and_encrypt(alice, bobs_public_key, &data).unwrap();
///
/// let message = webcryptobox::derive_and_decrypt(bob, alice_public_key, &encrypted_message);
/// ```
pub fn derive_and_decrypt(
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let key = derive_key(private_key, public_key).unwrap();

    decrypt(&key, data)
}
