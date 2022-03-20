# Webcryptobox
WebCrypto compatible encryption with Rust and its OpenSSL bindings.

This package implements the [Webcryptobox](https://github.com/jo/webcryptobox) encryption API.

Compatible packages:
* [Webcryptobox JavaScript](https://github.com/jo/webcryptobox-js)
* [Webcryptobox Bash](https://github.com/jo/webcryptobox-sh)

There is also a CLI tool: [wcb](https://github.com/jo/wcb-rs).

Convenient opinionated wrappers around [OpenSSL](https://docs.rs/openssl/latest/openssl/) to use [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) compatible cryptography. Webcryptobox helps with elliptic curve key generation, derivation, fingerprinting, import and export as well as AES encryption and decryption.

Documentation: [docs.rs/webcryptobox](https://docs.rs/webcryptobox/latest/webcryptobox/)


## Test
There's a test suite which ensures the lib works as expected. Run it with cargo:
```sh
cargo test
```


## License
This package is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

© 2022 Johannes J. Schmidt
