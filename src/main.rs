extern crate crypto;
extern crate serialize;
extern crate time;

use std::io::{ File, FileMode, FileAccess, Seek, SeekStyle };
use std::io::fs::PathExtensions;
use std::num::Float;
use std::f64::to_str_exact;
use std::os;
use std::ops::Add;
use std::str;
use std::string;
use std::rand::{ Rng, OsRng };

use serialize::base64::{ ToBase64, STANDARD };
use time::precise_time_s;

use crypto::{ scrypt, symmetriccipher, salsa20, mac, blake2b };
use crypto::scrypt::{ ScryptParams };
use crypto::symmetriccipher::{ SynchronousStreamCipher };
use crypto::mac::{ Mac };
use crypto::util::{ fixed_time_eq };


fn process_file(inputReader: &mut File, outputWriter: &mut File, encrypting : bool, payloadLength : u64, cipherKey: &[u8], nonce: &[u8], macKey: &[u8]) -> ([u8; 64], u64) {
    let mut xsalsa = salsa20::Salsa20::new_xsalsa20(cipherKey, nonce);
    let mut blake = blake2b::Blake2b::new_keyed(64, macKey);
    let mut bufferIn : [u8; 8192] = [0; 8192]; // 8 KB
    let mut bufferOut : [u8; 8192] = [0; 8192];
    let mut length = payloadLength;

    if encrypting {
        loop {
            match inputReader.read(&mut bufferIn) {
                Ok(n) => {
                    length += n as u64;
                    if n < 8192 {
                        xsalsa.process(&bufferIn[0..n], &mut bufferOut[0..n]);
                        blake.input(&bufferOut[0..n]);
                        outputWriter.write(&bufferOut[0..n]);
                        break;
                    }
                    xsalsa.process(&bufferIn, &mut bufferOut);
                    blake.input(&bufferOut);
                    outputWriter.write(&bufferOut);
                },
                Err(e) => panic!("Error reading: {}", e)
            }
        }
    } else {
        loop {
            if length > 8192 {           
                match inputReader.read(&mut bufferIn) {
                    Ok(nread) => {
                        if nread < 8192 {
                            panic!("Insufficient data. File may have been truncated, or the header has been modified.");
                        }
                        blake.input(&bufferIn);
                        xsalsa.process(&bufferIn, &mut bufferOut);
                    },
                    Err(e) => panic!("Error reading: {}", e)
                }
                outputWriter.write(&bufferOut);
                length -= 8192;
            } else {
                // At the end of the file
                match inputReader.read_exact(length as usize) {
                    Ok(finalInputVec) => {
                        let finalInput = finalInputVec.as_slice();
                        blake.input(finalInput);
                        xsalsa.process(finalInput, &mut bufferOut[0..length as usize]);                   
                        outputWriter.write(&bufferOut[0..length as usize]);
                    },
                    Err(e) => panic!("Error reading: {}", e)
                }
                break;
            }
        }
    }

    let mut mac : [u8; 64] = [0; 64];
    blake.raw_result(&mut mac);
    if !encrypting {
        length = payloadLength;
    }
    (mac, length as u64)
}

fn main() {
    // Input part

    let args = os::args();
    if args.len() != 3 {
        panic!("Incorrect number of arguments supplied.");
    }

    let encrypting;
    match args[1].as_slice() {
        "-e" => encrypting = true,
        "-d" => encrypting = false,
        _ => panic!("Neither -e (encrypt) or -d (decrypt) argument was provided.")
    }
    let ref inPathStr = args[2];
    let inPath = Path::new(inPathStr);
    if !inPath.exists() {
        println!("Input path \"{}\" provided does not exist.", inPathStr);
    } else {
        println!("Input: {}", inPath.filename_str().unwrap());
    }

    let encryptedExtension = ".crypted";
    let outPath = 
        if encrypting { 
            match inPath.extension_str() {
                Some(ext) => {
                    let mut ext_c = ext.to_string().add(encryptedExtension);
                    inPath.with_extension(ext_c.as_slice())
                },
                None => inPath.with_extension(encryptedExtension)
            }
        } else {
            let mut ext = inPath.filename_str().unwrap().to_string();
            let ext_newlen = ext.len() - encryptedExtension.len();
            ext.truncate(ext_newlen);
            inPath.with_filename(ext)
        };
    println!("Output: {}", outPath.filename_str().unwrap());

    let mut inFile = match File::open_mode(&inPath, FileMode::Open, FileAccess::Read) {
        Ok(f) => f,
        Err(e) => panic!("Cannot open input for reading: {}", e)
    };

    let mut outFile = match File::open_mode(&outPath, FileMode::Truncate, FileAccess::Write) {
        Ok(f) => f,
        Err(e) => panic!("Cannot open output for writing: {}", e)
    };

    // Header structure: KDF PARAMS || SALT || NONCE || PAYLOAD_LENGTH
    // Payload structure: PAYLOAD || MAC
    
    let mut work_factor : u8 = 12;
    let mut block_size : u8 = 16;
    let mut parallelism : u8 = 2;
    let mut scrypt_param_triple : [u8; 3] = [0; 3];
    let mut salt : [u8; 64] = [0; 64];
    let mut nonce : [u8; 24] = [0; 24];
    let mut payloadLength = 0;
    let mut payloadOffset = 0; // not in header. for internal use.
    
    if encrypting {
        scrypt_param_triple[0] = work_factor; // N
        scrypt_param_triple[1] = block_size; // r
        scrypt_param_triple[2] = parallelism; // p
        outFile.write(&scrypt_param_triple);
        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        outFile.write(&salt);
        outFile.write(&nonce);
        //payloadLength = inPath.stat().ok().unwrap().size;
        payloadOffset = outFile.tell().ok().unwrap();
        outFile.write_le_u64(payloadLength);
    } else {
        match inFile.read(&mut scrypt_param_triple) {
            Ok(i) => {
                if i < 3 {
                    panic!("KDF (scrypt) parameter block unable to be read in full, file may have been truncated.");
                }
            },
            Err(e) => panic!("Cannot read KDF parameters.")
        };
        // Seperate out the triple _^o^_
        work_factor = scrypt_param_triple[0];
        block_size = scrypt_param_triple[1];
        parallelism = scrypt_param_triple[2];
        // Onward!
        match inFile.read(&mut salt) {
            Ok(i) => {
                if i < salt.len() {
                    panic!("Salt was unable to be read in full, file may have been truncated.");
                }
            },
            Err(e) => panic!("Cannot read salt.")
        };
        match inFile.read(&mut nonce) {
            Ok(i) => {
                if i < nonce.len() {
                    panic!("Nonce was unable to be read in full, file may have been truncated.");
                }
            },
            Err(e) => panic!("Cannot read nonce.")
        };
        payloadLength = match inFile.read_le_u64() {
            Ok(l) => l,
            Err(e) => panic!("Cannot read payload length.")
        };
        println!("Payload length: {}", payloadLength);
    }

    println!("Enter the passphrase : ");
    let passphrase = std::io::stdin().read_line().ok().expect("Failed to read line.");

    // Cryptographic part

    let params = ScryptParams::new(work_factor, block_size as u32, parallelism as u32); // N, r, p
    println!("Deriving working cipher and MAC keys with KDF (scrypt) ...");
    println!("Work factor: {} , block size: {} , parallelism: {}", work_factor, block_size, parallelism);
    let mut stretchedKey : [u8; 96] = [0; 96]; // 32 bytes for cipher key, 64 bytes for mac key = 96 bytes
    let startKdfTime : f64 = precise_time_s();
    crypto::scrypt::scrypt(passphrase.as_bytes(), &salt, &params, &mut stretchedKey);
    let endKdfTime : f64 = precise_time_s();
    let kdfTime = endKdfTime - startKdfTime;
    println!("Keys derived in {} milliseconds.", to_str_exact(kdfTime * 1000.0f64, 3));

    println!("Running encryption/decryption process ... please wait");
    println!("Cryptographic details: Encrypt-then-MAC (EtM) with XSalsa20/BLAKE-2B-512.");
    let startCryptTime : f64 = precise_time_s();
    let (mac, ref payloadLength) = process_file(&mut inFile, &mut outFile, encrypting, payloadLength, &stretchedKey[0..32], &nonce, &stretchedKey[32..96]);
    let endCryptTime : f64 = precise_time_s();
    let cryptTime = endCryptTime - startCryptTime;

    const MEGABYTE: i32 = 1024 * 1024;
    let payload_megabytes = *payloadLength as f64 / MEGABYTE as f64;
    let mbps = payload_megabytes / cryptTime;

    if encrypting {
        outFile.write(&mac);
        outFile.seek(payloadOffset as i64, SeekStyle::SeekSet);
        outFile.write_le_u64(*payloadLength);
        println!("File was encrypted successfully at {} MB/s.", to_str_exact(mbps, 3));
    } else {
        let mut expectedMac : [u8; 64] = [0; 64];
        match inFile.read(&mut expectedMac) {
            Ok(n) => {
                if n < 64 {
                    panic!("Could not read MAC authentication data. Input file may be truncated.")
                }
            }
             Err(e) => panic!("Could not read MAC authentication data from input file: {}", e)
        };
        if fixed_time_eq(&mac, &expectedMac) {
            println!("File was decrypted successfully at {} MB/s.", to_str_exact(mbps, 3));
        } else {
            println!("WARNING: Authentication failed! Data may have been forged by a malicious actor.");
            println!("Expected MAC: {} . Found: {} .", expectedMac.to_base64(STANDARD).to_string(), mac.to_base64(STANDARD).to_string());
        }
    }
}