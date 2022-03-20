## v2.0.0 - Selected Cipher
Back to a flattened version with selected cipher: ECDH P-521 AES-256-CBC.

**Features:**
* initialization vector included in cipher, no manual iv generation needed anymore
* import and export encrypted private key pems

**Breaking change:**
* removed struct `Webcryptobox`. All methods are exported directly.
* removed CLI, this one went into its own project: https://github.com/jo/wcb-rs
* `derivePrivateKey` has been renamed to `getPrivateKey`

## v1.0.5 - More Examples
Adds a highlevel example

## v1.0.4 - Docs Improved II
Further improved documentation

## v1.0.3 - Docs Improved
More examples

## v1.0.2 - Doc Examples
Use executing examples

## v1.0.1 - Package Metadata
Add package metadata such as repository etc.

## v1.0.0 - Hello World!
Initial release of Webcryptobox
