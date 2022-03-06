//! Webcryptobox provides convenient wrappers around OpenSSL to use WebCrypto compatible
//! cryptography.
//!
//! It works nicely together with the [JavaScript Webcryptobox](https://github.com/jo/webcryptobox-js).
//!
//! Webcryptobox provides functions for elliptic curve key generation, derivation, import and
//! export as well as AES encryption and decryption.

use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::{Private, Public};
use openssl::rand::rand_bytes;
use openssl::sha;
use openssl::symm;

const AEAD_TAG_LENGTH: usize = 16;

/// Holds cipher configuration and provides the methods for dancing with elliptic curves and advanced encryption.
pub struct Webcryptobox {
    is_aead: bool,
    group: EcGroup,
    cipher: symm::Cipher,
}

impl Webcryptobox {
    /// Creates a new Webcryptobox.
    ///
    /// ```rs
    /// let wcb = Webcryptobox::new("P-256", "CBC", 128);
    /// ```
    /// This example uses the curve `P-256`, AES in `CBC` mode with a key length of 128.
    ///
    /// **Supported Curves:**
    /// * `P-256` [openssl::Nid::X9_62_PRIME256V1`] aka `secp256r1` or `prime256v1`
    /// * `P-384` [openssl::Nid::SECP384R1`] aka `secp384r1` or `ansip384r1`
    /// * `P-521` [openssl::Nid::SECP521R1`] aka `secp521r1` or `ansip521r1`
    ///
    /// **Supported AES Modes:**
    /// * `CBC`: Cipher Block Chaining Mode
    /// * `GCM`: Galois/Counter Mode
    ///
    /// **Supported AES key Lengths:**
    /// * `128`
    /// * `256`
    pub fn new(curve: &str, mode: &str, length: usize) -> Webcryptobox {
        let curve = match curve {
            "P-256" => Nid::X9_62_PRIME256V1,
            "P-384" => Nid::SECP384R1,
            "P-521" => Nid::SECP521R1,

            _ => panic!("Unsupported curve '{}'", curve),
        };

        let cipher = match mode {
            "CBC" => match length {
                128 => symm::Cipher::aes_128_cbc(),
                256 => symm::Cipher::aes_256_cbc(),
                _ => panic!("Unsupported length '{}'", length),
            },
            "GCM" => match length {
                128 => symm::Cipher::aes_128_gcm(),
                256 => symm::Cipher::aes_256_gcm(),
                _ => panic!("Unsupported length '{}'", length),
            },

            _ => panic!("Unsupported mode '{}'", mode),
        };

        let group = EcGroup::from_curve_name(curve).unwrap();
        let is_aead = mode == "GCM";

        Webcryptobox {
            group,
            cipher,
            is_aead,
        }
    }

    /// Creates a Webcryptobox with defaults (`curve=P-521, mode=GCM, length=256`).
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// ```
    pub fn default() -> Webcryptobox {
        let curve = Nid::SECP521R1;
        let group = EcGroup::from_curve_name(curve).unwrap();
        let cipher = symm::Cipher::aes_256_gcm();

        Webcryptobox {
            is_aead: true,
            group,
            cipher,
        }
    }

    /// Generate an EC private key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair();
    /// ```
    pub fn generate_key_pair(&self) -> Result<EcKey<Private>, ErrorStack> {
        EcKey::generate(&self.group)
    }

    /// Given a private EC key, derives the public EC key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let public_key = wcb.derive_public_key(&key);
    /// ```
    pub fn derive_public_key(
        &self,
        private_key: &EcKey<Private>,
    ) -> Result<EcKey<Public>, ErrorStack> {
        let key_point = private_key.public_key();

        EcKey::from_public_key(&self.group, &key_point)
    }

    /// Import a private key PEM.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let pem = (b"-----BEGIN PRIVATE KEY-----
    /// MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBcf8zEjlssqn4aTEB
    /// RR43ofwH/4BAXDAAd83Kz1Dyd+Ko0pit4ESgqSu/bJMdnDrpiGYuz0Klarwip8LD
    /// rYd9mEahgYkDgYYABAF2Nu9XKPs2CVFocuqCfaX5FzDUt6/nT/3Evqq8jBhK/ziN
    /// TrEs4wkZjuei5TS25aabX6iMex3etoN/GOw1KYpI4QBtIUnWudG8FT8N+USHSL9G
    /// h9fi+Yofeq4Io9DxPU1ChCKPIoQ6ORAMWoOCk9bTdIy6yqx33+RIM04wub4QAgDo
    /// LQ==
    /// -----END PRIVATE KEY-----").to_vec();
    /// let key = wcb.import_private_key_pem(&pem);
    /// ```
    pub fn import_private_key_pem(&self, pem: &[u8]) -> Result<EcKey<Private>, ErrorStack> {
        EcKey::private_key_from_pem(pem)
    }

    /// Import a public key PEM.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let pem = (b"-----BEGIN PUBLIC KEY-----
    /// MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBdjbvVyj7NglRaHLqgn2l+Rcw1Lev
    /// 50/9xL6qvIwYSv84jU6xLOMJGY7nouU0tuWmm1+ojHsd3raDfxjsNSmKSOEAbSFJ
    /// 1rnRvBU/DflEh0i/RofX4vmKH3quCKPQ8T1NQoQijyKEOjkQDFqDgpPW03SMusqs
    /// d9/kSDNOMLm+EAIA6C0=
    /// -----END PUBLIC KEY-----").to_vec();
    /// let key = wcb.import_public_key_pem(&pem);
    /// ```
    pub fn import_public_key_pem(&self, pem: &[u8]) -> Result<EcKey<Public>, ErrorStack> {
        EcKey::public_key_from_pem(pem)
    }

    /// Export a private EC key in PEM format.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let pem = wcb.export_private_key_pem(key);
    /// ```
    pub fn export_private_key_pem(
        &self,
        private_key: EcKey<Private>,
    ) -> Result<Vec<u8>, ErrorStack> {
        let key = PKey::from_ec_key(private_key).unwrap();
        key.private_key_to_pem_pkcs8()
    }

    /// Export a public EC key in PEM format.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let public_key = wcb.derive_public_key(&key).unwrap();
    /// let pem = wcb.export_public_key_pem(&public_key);
    /// ```
    pub fn export_public_key_pem(&self, public_key: &EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
        public_key.public_key_to_pem()
    }

    /// Calculate a SHA-1 fingeprint from a private key.
    ///
    /// This hashes the DER data of the public key part of the key. Note this does not create a
    /// hash of the private key, but the public key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let fingerprint = wcb.sha1_fingerprint_from_private_key(&key);
    /// ```
    pub fn sha1_fingerprint_from_private_key(
        &self,
        key: &EcKey<Private>,
    ) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha1::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    /// Calculate a SHA-1 fingeprint from a public key.
    ///
    /// This hashes the DER data of the key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let public_key = wcb.derive_public_key(&key).unwrap();
    /// let fingerprint = wcb.sha1_fingerprint_from_public_key(&public_key);
    /// ```
    pub fn sha1_fingerprint_from_public_key(
        &self,
        key: &EcKey<Public>,
    ) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha1::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    /// Calculate a SHA-256 fingeprint from a private key.
    ///
    /// This hashes the DER data of the public key part of the key. Note this does not create a
    /// hash of the private key, but the public key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let fingerprint = wcb.sha256_fingerprint_from_private_key(&key);
    /// ```
    pub fn sha256_fingerprint_from_private_key(
        &self,
        key: &EcKey<Private>,
    ) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha256::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    /// Calculate a SHA-256 fingeprint from a public key.
    ///
    /// This hashes the DER data of the key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key_pair().unwrap();
    /// let public_key = wcb.derive_public_key(&key).unwrap();
    /// let fingerprint = wcb.sha256_fingerprint_from_public_key(&public_key);
    /// ```
    pub fn sha256_fingerprint_from_public_key(
        &self,
        key: &EcKey<Public>,
    ) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha256::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    /// Generate AES key material to be used with `encrypt` and `decrypt`.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key();
    /// ```
    pub fn generate_key(&self) -> Result<Vec<u8>, ErrorStack> {
        match self.cipher.key_len() {
            16 => {
                let mut key = [0; 16];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            }
            32 => {
                let mut key = [0; 32];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            }
            _ => panic!("unknown size"),
        }
    }

    /// Derives AES key material to be used with `encrypt` and `decrypt` from given private and
    /// public key.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let alice = wcb.generate_key_pair().unwrap();
    /// let bob = wcb.generate_key_pair().unwrap();
    /// let bobs_public_key = wcb.derive_public_key(&bob).unwrap();
    /// let key = wcb.derive_key(alice, bobs_public_key);
    /// ```
    pub fn derive_key(
        &self,
        private_key: EcKey<Private>,
        public_key: EcKey<Public>,
    ) -> Result<Vec<u8>, ErrorStack> {
        let private_key = PKey::from_ec_key(private_key).unwrap();
        let public_key = PKey::from_ec_key(public_key).unwrap();

        let mut deriver = Deriver::new(&private_key).unwrap();
        deriver.set_peer(&public_key).unwrap();

        match self.cipher.key_len() {
            16 => {
                let mut key: [u8; 16] = [0; 16];
                deriver.derive(&mut key).unwrap();
                Ok(key.to_vec())
            }
            32 => {
                let mut key: [u8; 32] = [0; 32];
                deriver.derive(&mut key).unwrap();
                Ok(key.to_vec())
            }
            _ => panic!("unknown key size"),
        }
    }

    /// Generate AES initialization vector to be used with `encrypt` and `decrypt`.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let iv = wcb.generate_iv();
    /// ```
    pub fn generate_iv(&self) -> Result<Vec<u8>, ErrorStack> {
        match self.cipher.iv_len() {
            Some(12) => {
                let mut key: [u8; 12] = [0; 12];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            }
            Some(16) => {
                let mut key: [u8; 16] = [0; 16];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            }
            _ => panic!("unknown iv size"),
        }
    }

    /// Encrypts data with key and iv.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    /// let key = wcb.generate_key().unwrap();
    /// let iv = wcb.generate_iv().unwrap();
    /// let data = (b"a secret message").to_vec();
    /// let encrypted_message = wcb.encrypt(&key, &iv, &data);
    /// ```
    pub fn encrypt(&self, key: &[u8], iv: &Vec<u8>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        match self.is_aead {
            true => {
                let mut tag: [u8; AEAD_TAG_LENGTH] = [0; AEAD_TAG_LENGTH];
                let mut ciphertext =
                    symm::encrypt_aead(self.cipher, key, Some(iv), &[], data, &mut tag).unwrap();
                ciphertext.extend(tag);
                Ok(ciphertext)
            }
            false => symm::encrypt(self.cipher, key, Some(iv), data),
        }
    }

    /// Decrypts data with key and iv.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    ///
    /// let key = wcb.generate_key().unwrap();
    /// let iv = wcb.generate_iv().unwrap();
    /// let data = (b"a secret message").to_vec();
    /// let encrypted_message = wcb.encrypt(&key, &iv, &data).unwrap();
    ///
    /// let message = wcb.decrypt(&key, &iv, &encrypted_message);
    /// ```
    pub fn decrypt(&self, key: &[u8], iv: &Vec<u8>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        match self.is_aead {
            true => {
                let tag_start = data.len() - AEAD_TAG_LENGTH;
                let d = &data[0..tag_start];
                let tag = &data[tag_start..];
                symm::decrypt_aead(self.cipher, key, Some(iv), &[], &d, &tag)
            }
            false => symm::decrypt(self.cipher, key, Some(iv), &data),
        }
    }

    /// Derives AES key from given private and public key and encrypts message.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    ///
    /// let alice = wcb.generate_key_pair().unwrap();
    /// let bob = wcb.generate_key_pair().unwrap();
    /// let bobs_public_key = wcb.derive_public_key(&bob).unwrap();
    ///
    /// let iv = wcb.generate_iv().unwrap();
    /// let data = (b"a secret message").to_vec();
    /// let encrypted_message = wcb.derive_and_encrypt(alice, bobs_public_key, &iv, &data);
    /// ```
    pub fn derive_and_encrypt(
        &self,
        private_key: EcKey<Private>,
        public_key: EcKey<Public>,
        iv: &Vec<u8>,
        data: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        let key = self.derive_key(private_key, public_key).unwrap();

        self.encrypt(&key, iv, data)
    }

    /// Derives AES key from given private and public key and decrypts message.
    ///
    /// # Example:
    ///
    /// ```rust
    /// let wcb = webcryptobox::Webcryptobox::default();
    ///
    /// let alice = wcb.generate_key_pair().unwrap();
    /// let bob = wcb.generate_key_pair().unwrap();
    /// let bobs_public_key = wcb.derive_public_key(&bob).unwrap();
    /// let alice_public_key = wcb.derive_public_key(&alice).unwrap();
    ///
    /// let iv = wcb.generate_iv().unwrap();
    /// let data = (b"a secret message").to_vec();
    /// let encrypted_message = wcb.derive_and_encrypt(alice, bobs_public_key, &iv, &data).unwrap();
    ///
    /// let message = wcb.derive_and_decrypt(bob, alice_public_key, &iv, &encrypted_message);
    /// ```
    pub fn derive_and_decrypt(
        &self,
        private_key: EcKey<Private>,
        public_key: EcKey<Public>,
        iv: &Vec<u8>,
        data: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        let key = self.derive_key(private_key, public_key).unwrap();

        self.decrypt(&key, iv, data)
    }
}
