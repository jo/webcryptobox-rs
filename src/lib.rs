use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::derive::Deriver;
use openssl::pkey::PKey;
use openssl::symm;
use openssl::sha;


const AEAD_TAG_LENGTH: usize = 16;

pub struct Webcryptobox {
    is_aead: bool,
    group: EcGroup,
    cipher: symm::Cipher
}

impl Webcryptobox {
    pub fn default() -> Webcryptobox {
        let curve = Nid::SECP521R1;
        let group = EcGroup::from_curve_name(curve).unwrap();
        let cipher = symm::Cipher::aes_256_gcm();

        Webcryptobox {
            is_aead: true,
            group,
            cipher
        }
    }

    pub fn new(curve: &str, mode: &str, length: usize) -> Webcryptobox {
        let curve = match curve {
            "P-256" => Nid::X9_62_PRIME256V1,
            "P-384" => Nid::SECP384R1,
            "P-521" => Nid::SECP521R1,

            _ => panic!("Unsupported curve '{}'", curve)
        };

        let cipher = match mode {
            "CBC" => match length {
                128 => symm::Cipher::aes_128_cbc(),
                256 => symm::Cipher::aes_256_cbc(),
                _ => panic!("Unsupported length '{}'", length)
            },
            "GCM" => match length {
                128 => symm::Cipher::aes_128_gcm(),
                256 => symm::Cipher::aes_256_gcm(),
                _ => panic!("Unsupported length '{}'", length)
            },

            _ => panic!("Unsupported mode '{}'", mode)
        };
        
        let group = EcGroup::from_curve_name(curve).unwrap();
        let is_aead = mode == "GCM";

        Webcryptobox {
            group,
            cipher,
            is_aead
        }
    }

    pub fn generate_key_pair(&self) -> Result<EcKey<Private>, ErrorStack> {
        EcKey::generate(&self.group)
    }

    pub fn derive_public_key(&self, private_key: &EcKey<Private>) -> Result<EcKey<Public>, ErrorStack> {
        let key_point = private_key.public_key();
        
        EcKey::from_public_key(&self.group, &key_point)
    }

    pub fn import_private_key_pem(&self, pem: &[u8]) -> Result<EcKey<Private>, ErrorStack> {
        EcKey::private_key_from_pem(pem)
    }

    pub fn import_public_key_pem(&self, pem: &[u8]) -> Result<EcKey<Public>, ErrorStack> {
        EcKey::public_key_from_pem(pem)
    }

    pub fn export_private_key_pem(&self, private_key: EcKey<Private>) -> Result<Vec<u8>, ErrorStack> {
        let key = PKey::from_ec_key(private_key).unwrap();
        key.private_key_to_pem_pkcs8()
    }

    pub fn export_public_key_pem(&self, public_key: &EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
        public_key.public_key_to_pem()
    }

    pub fn sha1_fingerprint_from_private_key(&self, key: &EcKey<Private>) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha1::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    pub fn sha1_fingerprint_from_public_key(&self, key: &EcKey<Public>) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha1::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    pub fn sha256_fingerprint_from_private_key(&self, key: &EcKey<Private>) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha256::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    pub fn sha256_fingerprint_from_public_key(&self, key: &EcKey<Public>) -> Result<String, ErrorStack> {
        let der = key.public_key_to_der().unwrap();
        let mut hasher = sha::Sha256::new();
        hasher.update(&der);
        let hash = hasher.finish();
        let hex = hex::encode(hash);

        Ok(hex)
    }

    pub fn generate_key(&self) -> Result<Vec<u8>, ErrorStack> {
        match self.cipher.key_len() {
            16 => {
                let mut key = [0; 16];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            },
            32 => {
                let mut key = [0; 32];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            },
            _ => panic!("unknown size")
        }
    }

    pub fn derive_key(&self, private_key: EcKey<Private>, public_key: EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
        let private_key = PKey::from_ec_key(private_key).unwrap();
        let public_key = PKey::from_ec_key(public_key).unwrap();

        let mut deriver = Deriver::new(&private_key).unwrap();
        deriver.set_peer(&public_key).unwrap();
        
        match self.cipher.key_len() {
            16 => {
                let mut key: [u8; 16] = [0; 16];
                deriver.derive(&mut key).unwrap();
                Ok(key.to_vec())
            },
            32 => {
                let mut key: [u8; 32] = [0; 32];
                deriver.derive(&mut key).unwrap();
                Ok(key.to_vec())
            },
            _ => panic!("unknown key size")
        }
    }

    pub fn generate_iv(&self) -> Result<Vec<u8>, ErrorStack> {
        match self.cipher.iv_len() {
            Some(12) => {
                let mut key: [u8; 12] = [0; 12];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            },
            Some(16) => {
                let mut key: [u8; 16] = [0; 16];
                rand_bytes(&mut key).unwrap();
                Ok(key.to_vec())
            },
            _ => panic!("unknown iv size")
        }
    }

    pub fn encrypt(&self, key: &[u8], iv: &Vec<u8>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        match self.is_aead {
            true => {
                let mut tag: [u8; AEAD_TAG_LENGTH] = [0; AEAD_TAG_LENGTH];
                let mut ciphertext = symm::encrypt_aead(
                    self.cipher,
                    key,
                    Some(iv),
                    &[],
                    data,
                    &mut tag
                ).unwrap();
                ciphertext.extend(tag);
                Ok(ciphertext)
            },
            false => {
                symm::encrypt(
                    self.cipher,
                    key,
                    Some(iv),
                    data
                )
            }
        }
    }

    pub fn decrypt(&self, key: &[u8], iv: &Vec<u8>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        match self.is_aead {
            true => {
                let tag_start = data.len() - AEAD_TAG_LENGTH;
                let d = &data[0..tag_start];
                let tag = &data[tag_start..];
                symm::decrypt_aead(
                    self.cipher,
                    key,
                    Some(iv),
                    &[],
                    &d,
                    &tag
                )
            },
            false => {
                symm::decrypt(
                    self.cipher,
                    key,
                    Some(iv),
                    &data
                )
            }
        }
    }

    pub fn derive_and_encrypt(&self, private_key: EcKey<Private>, public_key: EcKey<Public>, iv: &Vec<u8>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let key = self.derive_key(private_key, public_key).unwrap();

        self.encrypt(&key, iv, data)
    }

    pub fn derive_and_decrypt(&self, private_key: EcKey<Private>, public_key: EcKey<Public>, iv: &Vec<u8>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let key = self.derive_key(private_key, public_key).unwrap();

        self.decrypt(&key, iv, data)
    }
}
