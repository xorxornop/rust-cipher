# rust-cipher

My first attempt at a rust application.
It uses XSalsa20 and BLAKE2B-512 in the Encrypt-then-MAC mode of use to encrypt/decrypt and authenticate a file passed in by argument. Working keys are derived with a KDF (scrypt) from a passphrase. Parameters for scrypt: 12, 8, 2 (N, r, p). KDF parameters and salt, cipher nonce, etc are stored in a header and are read in. This means scrypt parameters can be changed without changing the file format. Ability to modify parameters could be added as commandline arguments.

## How to use?

./rust-cipher -e my_file.ext
Outputs a file named my_file.ext.crypted

./rust-cipher -d my_file.ext.crypted
Outputs a file named my_file.ext

(your_file is whatever you want it to be)

## Acknowledgements
[rust-crypto](https://github.com/DaGenix/rust-crypto)
