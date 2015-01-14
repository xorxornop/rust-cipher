# rust-cipher

My first attempt at a rust application.
It uses XSalsa20 and BLAKE2B-512 in the Encrypt-then-MAC mode of use to encrypt/decrypt and authenticate a file passed in by argument.

## How to use?

./rust-cipher -e my_file.ext
Outputs a file named my_file.ext.crypted

./rust-cipher -d my_file.ext.crypted
Outputs a file named my_file.ext

(your_file is whatever you want it to be)

## Acknowledgements
[rust-crypto](https://github.com/DaGenix/rust-crypto)
