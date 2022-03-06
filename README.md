# Webcryptobox
Webcryptobox provides convenient wrappers around OpenSSL to use WebCrypto compatible cryptography.

It works nicely together with the [JavaScript Webcryptobox](https://github.com/jo/webcryptobox-js).

Webcryptobox provides functions for elliptic curve key generation, derivation, import and export as well as AES encryption and decryption.

Webcryptobox comes with both a library and a little command line interface. For the library documentation, see [docs.rs/webcryptobox](https://docs.rs/webcryptobox/latest/webcryptobox/). In the following I describe the CLI usage.

## Installation
Clone the project, compile it and use the binary:

```sh
git clone https://github.com/jo/webcryptobox-js
cd webcryptobox-js
cargo build --release
sudo ln -s `pwd`/target/release/webcryptobox /usr/local/bin/webcryptobox
```

## Usage
Webcryptobox prints out usage information if you do not provide any argument, or if the command is not recognized.

### Configuration
Cipher selection is done via environment variables:

* `CURVE`: EC curve name. Defaults to `P-521`
* `MODE`: AES mode. Defaults to `GCM`
* `LENGTH`: AES key length in bits. Default is `256`

#### Supported EC Curves
* `P-256`: 256-bit prime field Weierstrass curve. Also known as `secp256r1` or `prime256v1`.
* `P-384`: 384-bit prime field Weierstrass curve. Also known as: `secp384r1` or `ansip384r1`.
* `P-521`: 521-bit prime field Weierstrass curve. Also known as: `secp521r1` or `ansip521r1`.

#### Supported AES Modes
* `CBC`: Cipher Block Chaining Mode
* `GCM`: Galois/Counter Mode

#### Supported AES Key Lengths
* `128`
* `256`

### `generate-key-pair`
Generate ECDH key and output private key as pem.

```sh
$ webcryptobox generate-key-pair
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIANqKw4HlT3vUqNQTg
YtueEyGDmnm8bOo50Gyq/Y7sSldOZzcPQ+WggGnGd62M6sYit3IZZ+/752OR7+8O
td1swiuhgYkDgYYABAGga0QN+HqG9QQwSACVUvts2AV8gbJ+iUKZJWWXQ5BcCoyX
RBVi21Ga0ViWQSXyump3H6YrdXq2+2QVKcpQMQmRZQB3P4K6+TqKX4RxXcLKdu0F
F7fvYfUXLAxh71MN6HUQDguJ2rwtiM9DfXBu/kqvMURPnb09Cv/ymXN6mU+iavJ9
3A==
-----END PRIVATE KEY-----
```

### `generate-key`
Generate AES key, output as hex.

```sh
$ webcryptobox generate-key
324cc75bdd8185e84c3f2ede3d67017f6fe22ad45dade188b8233dae0f836304
```

### `generate-iv`
Generate an initialization vector, output as hex.

```sh
$ webcryptobox generate-iv
a0e58789d6a4ffa9cec8bbd2
```

### `derive-public-key <filename>`
Derive public key from private key PEM file, output public key pem.

```sh
$ webcryptobox derive-public-key private-key.pem 
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBoGtEDfh6hvUEMEgAlVL7bNgFfIGy
folCmSVll0OQXAqMl0QVYttRmtFYlkEl8rpqdx+mK3V6tvtkFSnKUDEJkWUAdz+C
uvk6il+EcV3CynbtBRe372H1FywMYe9TDeh1EA4Lidq8LYjPQ31wbv5KrzFET529
PQr/8plzeplPomryfdw=
-----END PUBLIC KEY-----
```

### `sha1-fingerprint <filename>`
Calculate SHA-1 fingerprint from private or public key pem file, output hex. Works by hashing the DER contents of the public key part.

```sh
$ webcryptobox sha1-fingerprint private-key.pem 
e635c9976397b68fcc5a3e872fad6730c86e945b
```

### `sha256-fingerprint <filename>`
Calculate SHA-256 fingerprint from private or public key pem file, output hex. Works by hashing the DER contents of the public key part.

```sh
$ webcryptobox sha256-fingerprint private-key.pem 
bfeb4a6ea6c4be9117800516ebb4ca9527f106a3498e3684ee4dc291470752aa
```

### `derive-key <private-key> <peer-key>`
derive AES key from private and public key files as pem, output hex.

```sh
$ webcryptobox derive-key private-key.pem their-public-key.pem 
0028ca6b01e9b6293692217efe690bcc2e6537e18cbf3cf7e238adf99f2fe392
```

### `encrypt <key> <iv>`
reads message from STDIN and key and iv as hex args, encrypts message and prints out as base64.

```sh
$ echo "a secret message" \
  | webcryptobox encrypt \
    324cc75bdd8185e84c3f2ede3d67017f6fe22ad45dade188b8233dae0f836304 \
    a0e58789d6a4ffa9cec8bbd2
yMQpXTpEkXn9qcav4YJnudO3OB73ywKRnKjzNhckh3Pw
```

### `decrypt <key> <iv>`
reads encrypted message in base64 format from STDIN and key and iv as hex args and prints out decrypted message.

```sh
$ echo -n "yMQpXTpEkXn9qcav4YJnudO3OB73ywKRnKjzNhckh3Pw" \
  | webcryptobox decrypt \
    324cc75bdd8185e84c3f2ede3d67017f6fe22ad45dade188b8233dae0f836304 \
    a0e58789d6a4ffa9cec8bbd2
a secret message
```

### `derive-and-encrypt <private-key> <peer-key> <iv>`
reads message from STDIN and private and public key files as pem and iv as hex and encrypts message and prints out as base64.

```sh
$ echo "a secret message" \
  | webcryptobox derive-and-encrypt \
    my-private-key.pem \
    their-public-key.pem \
    b3b7013cdd605017fc1a4010
fBAXWxsdrctjXyceuuAfZMFWb6hLjFGOZAngYlbDTaq6
```

### ` derive-and-decrypt <private-key> <peer-key> <iv>`
reads encrypted message in base64 format from STDIN, private and public key files as pem and iv as hex and prints out decrypted message.

```sh
$ echo -n "fBAXWxsdrctjXyceuuAfZMFWb6hLjFGOZAngYlbDTaq6" \
  | webcryptobox derive-and-decrypt \
    their-private-key.pem \
    my-public-key.pem \
    b3b7013cdd605017fc1a4010
a secret message
```


## Test
There's a test suite which ensures the lib works as expected. Run it with cargo:
```sh
cargo test
```

## License
This package is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

© 2022 Johannes J. Schmidt
