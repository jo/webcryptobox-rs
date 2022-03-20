// TODO: test panic on unsupported cipher/curve name

#[cfg(test)]
mod tests {
    use webcryptobox::*;

    struct Peer {
        private_key_pem: Vec<u8>,
        encrypted_private_key_pem: Vec<u8>,
        public_key_pem: Vec<u8>,
        sha1_fingerprint: Vec<u8>,
        sha256_fingerprint: Vec<u8>,
        password: Vec<u8>,
    }

    struct Fixture<'a> {
        alice: &'a Peer,
        bob: &'a Peer,
        key: &'a Vec<u8>,
        passphrase: &'a [u8],
        message: &'a Vec<u8>,
    }

    fn setup<F: Fn(Fixture)>(f: F) {
        let alice = Peer {
            private_key_pem: (b"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBcf8zEjlssqn4aTEB
RR43ofwH/4BAXDAAd83Kz1Dyd+Ko0pit4ESgqSu/bJMdnDrpiGYuz0Klarwip8LD
rYd9mEahgYkDgYYABAF2Nu9XKPs2CVFocuqCfaX5FzDUt6/nT/3Evqq8jBhK/ziN
TrEs4wkZjuei5TS25aabX6iMex3etoN/GOw1KYpI4QBtIUnWudG8FT8N+USHSL9G
h9fi+Yofeq4Io9DxPU1ChCKPIoQ6ORAMWoOCk9bTdIy6yqx33+RIM04wub4QAgDo
LQ==
-----END PRIVATE KEY-----
")
            .to_vec(),
            encrypted_private_key_pem: (b"-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBZjBgBgkqhkiG9w0BBQ0wUzAyBgkqhkiG9w0BBQwwJQQQOG0vrzwWTXnZGV40
QTUa7gIDAPoAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBChJ598h/deO6WH
YdP1lue+BIIBAE9tqarEYD51VXFCPsbIT/CVaF7RJ4emUNvk29Q35hNcf+2CRCki
K8T23KAPQ7GFkHBdmykV2uNvZ+CWCeKeOqj9AZU36mHK4gkIQz1bgADRjRp/lb2j
mBvg7Yzm3+H67zRmkr44jdqc8BJFCeqaMH6Fm6XQR0IPtUhmrR8YZyc1ka9L5+IB
Qk+SWDXF0brMnpLiwdKPABb4qCJ49qNwR0xVGlYyAv/XdT5PkyzzZxpwv2hLv7zw
y9KnnZ4qA0ceNo4RBYuWALlfqWANARl8lAvHLdSedN7cW9lU2PyXB+70twInt4Ty
lkyFWM+JH9SavLEAdG1mPHnYJB1INSMifS0=
-----END ENCRYPTED PRIVATE KEY-----
")
            .to_vec(),
            public_key_pem: (b"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBdjbvVyj7NglRaHLqgn2l+Rcw1Lev
50/9xL6qvIwYSv84jU6xLOMJGY7nouU0tuWmm1+ojHsd3raDfxjsNSmKSOEAbSFJ
1rnRvBU/DflEh0i/RofX4vmKH3quCKPQ8T1NQoQijyKEOjkQDFqDgpPW03SMusqs
d9/kSDNOMLm+EAIA6C0=
-----END PUBLIC KEY-----
")
            .to_vec(),
            sha1_fingerprint: [
                217, 24, 41, 216, 252, 154, 40, 96, 142, 0, 113, 73, 225, 207, 60, 143, 53, 210,
                108, 95,
            ]
            .to_vec(),
            sha256_fingerprint: [
                12, 133, 132, 181, 164, 129, 56, 205, 224, 203, 55, 136, 115, 72, 112, 16, 138,
                144, 237, 10, 126, 182, 36, 152, 240, 12, 8, 56, 182, 134, 134, 83,
            ]
            .to_vec(),
            password: [
                23, 50, 99, 42, 30, 107, 207, 194, 114, 154, 137, 95, 160, 228, 81, 0,
            ]
            .to_vec(),
        };

        let bob = Peer {
            private_key_pem: (b"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAvVtKGBatnJz0J+Tt
L3MFjdHp4JXE4pVs+mUJNYaIxnLyLHnUDQhgNo6va7EJeupHDpL8ixwz6pb6qoZZ
x3G21wOhgYkDgYYABAFtE04yjeLeUC8V4RvDY6tlCv5wz5g8etFduTOqhYvw/GzN
aY1VbKa6W9MjlpYyYnfBQmyZCbvoeHTmULAWscQ8NAGCj9gH+T6D5lPhKR8WuNtB
CvKGKDtCwTxzJDFEo2F6ZhJ11ucV/sLNJrd62LXjN5aURArbSsEKuib7l4rvAN8A
0g==
-----END PRIVATE KEY-----
")
            .to_vec(),
            encrypted_private_key_pem: (b"-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBZjBgBgkqhkiG9w0BBQ0wUzAyBgkqhkiG9w0BBQwwJQQQPohe6UFhNdQ6Gyjo
bx6nbgIDAPoAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAIiD5rfJfi+SCD
oiVgZM90BIIBAOfdQgRSC9o/8MpH1Js7MgjUnCIVg/Ro68I3HEiWPSQFobzN8jyV
xjN5G+PIN8wve99/gsS5y3Ufwv+awIbHQup8P5dJjTagxgyw1nsjqcGJK6jVywYn
6HUjB1nj/nmL3DHR8IXerAeHk5UY9KfcYoLiKgQQS51p0smrwXVtJU628gEM0811
sSwm8E/9e6oKMYuUF2jGVKkJENpQZQgN4dLM+b2g8CtgLnPQynPneKvSt1vWClCl
OHd40qxDgZS3vGMr8+P7jEMvTpa2qdoz2oplYVKJmxjxVVBGJ0n1h7n2Nu74gDn0
g4xVxKF9UrxL4w15ENwd2syrOGP/WYwXEJ4=
-----END ENCRYPTED PRIVATE KEY-----
")
            .to_vec(),
            public_key_pem: (b"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBbRNOMo3i3lAvFeEbw2OrZQr+cM+Y
PHrRXbkzqoWL8PxszWmNVWymulvTI5aWMmJ3wUJsmQm76Hh05lCwFrHEPDQBgo/Y
B/k+g+ZT4SkfFrjbQQryhig7QsE8cyQxRKNhemYSddbnFf7CzSa3eti14zeWlEQK
20rBCrom+5eK7wDfANI=
-----END PUBLIC KEY-----
")
            .to_vec(),
            sha1_fingerprint: [
                18, 165, 252, 75, 127, 217, 77, 41, 29, 148, 248, 249, 225, 53, 118, 117, 180, 189,
                37, 200,
            ]
            .to_vec(),
            sha256_fingerprint: [
                253, 83, 151, 199, 141, 12, 36, 157, 134, 68, 8, 249, 207, 144, 153, 79, 62, 122,
                101, 5, 7, 123, 98, 98, 132, 90, 214, 214, 231, 96, 158, 156,
            ]
            .to_vec(),
            password: [
                83, 69, 95, 11, 20, 234, 22, 242, 79, 168, 68, 168, 60, 218, 169, 73,
            ]
            .to_vec(),
        };

        let key = [
            1, 111, 248, 82, 88, 255, 144, 7, 193, 187, 122, 192, 179, 225, 244, 241, 169, 215,
            155, 221, 71, 168, 123, 161, 82, 74, 117, 207, 48, 72, 78, 187,
        ]
        .to_vec();

        let passphrase = b"secret passphrase";
        let message = (b"a secret message").to_vec();

        f(Fixture {
            alice: &alice,
            bob: &bob,
            key: &key,
            passphrase,
            message: &message,
        });
    }

    #[test]
    fn test_generate_key_pair() {
        generate_private_key().unwrap();
    }

    #[test]
    fn test_get_public_key() {
        setup(|f| {
            let private_key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let public_key = get_public_key(&private_key).unwrap();
            let pem = export_public_key_pem(&public_key).unwrap();
            assert_eq!(f.alice.public_key_pem, pem);
        });
    }

    #[test]
    fn test_import_private_pem() {
        setup(|f| {
            import_private_key_pem(&f.alice.private_key_pem).unwrap();
        });
    }

    #[test]
    fn test_import_public_pem() {
        setup(|f| {
            import_public_key_pem(&f.alice.public_key_pem).unwrap();
        });
    }

    #[test]
    fn test_export_private_pem() {
        setup(|f| {
            let key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let pem = export_private_key_pem(key).unwrap();
            assert_eq!(f.alice.private_key_pem, pem);
        });
    }

    #[test]
    fn import_encrypted_private_pem() {
        setup(|f| {
            let private_key =
                import_encrypted_private_key_pem(&f.alice.encrypted_private_key_pem, f.passphrase)
                    .unwrap();
            let pem = export_private_key_pem(private_key).unwrap();
            assert_eq!(f.alice.private_key_pem, pem);
        });
    }

    #[test]
    fn test_export_encrypted_private_pem() {
        setup(|f| {
            let key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let passphrase = b"secret passphrase";
            export_encrypted_private_key_pem(key, passphrase).unwrap();
        });
    }

    #[test]
    fn test_export_public_pem() {
        setup(|f| {
            let key = import_public_key_pem(&f.alice.public_key_pem).unwrap();
            let pem = export_public_key_pem(&key).unwrap();
            assert_eq!(f.alice.public_key_pem, pem);
        });
    }

    #[test]
    fn test_sha1_fingerprint_from_alice_private_key() {
        setup(|f| {
            let key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let fingerprint = sha1_fingerprint_from_private_key(&key).unwrap();
            assert_eq!(f.alice.sha1_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha1_fingerprint_from_alice_public_key() {
        setup(|f| {
            let key = import_public_key_pem(&f.alice.public_key_pem).unwrap();
            let fingerprint = sha1_fingerprint_from_public_key(&key).unwrap();
            assert_eq!(f.alice.sha1_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha256_fingerprint_from_alice_private_key() {
        setup(|f| {
            let key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let fingerprint = sha256_fingerprint_from_private_key(&key).unwrap();
            assert_eq!(f.alice.sha256_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha256_fingerprint_from_alice_public_key() {
        setup(|f| {
            let key = import_public_key_pem(&f.alice.public_key_pem).unwrap();
            let fingerprint = sha256_fingerprint_from_public_key(&key).unwrap();
            assert_eq!(f.alice.sha256_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha1_fingerprint_from_bob_private_key() {
        setup(|f| {
            let key = import_private_key_pem(&f.bob.private_key_pem).unwrap();
            let fingerprint = sha1_fingerprint_from_private_key(&key).unwrap();
            assert_eq!(f.bob.sha1_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha1_fingerprint_from_bob_public_key() {
        setup(|f| {
            let key = import_public_key_pem(&f.bob.public_key_pem).unwrap();
            let fingerprint = sha1_fingerprint_from_public_key(&key).unwrap();
            assert_eq!(f.bob.sha1_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha256_fingerprint_from_bob_private_key() {
        setup(|f| {
            let key = import_private_key_pem(&f.bob.private_key_pem).unwrap();
            let fingerprint = sha256_fingerprint_from_private_key(&key).unwrap();
            assert_eq!(f.bob.sha256_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_sha256_fingerprint_from_bob_public_key() {
        setup(|f| {
            let key = import_public_key_pem(&f.bob.public_key_pem).unwrap();
            let fingerprint = sha256_fingerprint_from_public_key(&key).unwrap();
            assert_eq!(f.bob.sha256_fingerprint, fingerprint);
        });
    }

    #[test]
    fn test_generate_key() {
        generate_key().unwrap();
    }

    #[test]
    fn test_derive_key() {
        setup(|f| {
            let alice_private_key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let alice_public_key = import_public_key_pem(&f.alice.public_key_pem).unwrap();

            let bob_private_key = import_private_key_pem(&f.bob.private_key_pem).unwrap();
            let bob_public_key = import_public_key_pem(&f.bob.public_key_pem).unwrap();

            let alice_shared_key = derive_key(alice_private_key, bob_public_key).unwrap();
            assert_eq!(f.key, &alice_shared_key);

            let bob_shared_key = derive_key(bob_private_key, alice_public_key).unwrap();
            assert_eq!(f.key, &bob_shared_key);
        });
    }

    #[test]
    fn test_derive_password() {
        setup(|f| {
            let alice_private_key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let alice_public_key = get_public_key(&alice_private_key).unwrap();
            let alice_password = derive_password(alice_private_key, alice_public_key, &16).unwrap();
            assert_eq!(f.alice.password, alice_password);

            let bob_private_key = import_private_key_pem(&f.bob.private_key_pem).unwrap();
            let bob_public_key = get_public_key(&bob_private_key).unwrap();
            let bob_password = derive_password(bob_private_key, bob_public_key, &16).unwrap();
            assert_eq!(f.bob.password, bob_password);
        });
    }

    #[test]
    fn test_encrypt_then_decrypt() {
        setup(|f| {
            let ciphertext = encrypt(&f.key, &f.message).unwrap();
            let message = decrypt(&f.key, &ciphertext).unwrap();
            assert_eq!(f.message, &message);
        });
    }

    #[test]
    fn test_derive_and_encrypt_then_decrypt() {
        setup(|f| {
            let alice_private_key = import_private_key_pem(&f.alice.private_key_pem).unwrap();
            let bob_public_key = import_public_key_pem(&f.bob.public_key_pem).unwrap();
            let ciphertext =
                derive_and_encrypt(alice_private_key, bob_public_key, &f.message).unwrap();
            let bob_private_key = import_private_key_pem(&f.bob.private_key_pem).unwrap();
            let alice_public_key = import_public_key_pem(&f.alice.public_key_pem).unwrap();
            let message =
                derive_and_decrypt(bob_private_key, alice_public_key, &ciphertext).unwrap();
            assert_eq!(f.message, &message);
        });
    }
}
