//! # ChaCha20
//! Used for encryption and decryption of any file less
//! then 256 gb using chacha20 algorithm.

use std::env;
use std::fs::File;
use std::io::prelude::*;

fn main(){
    let (input_file, key_file, nonce_file, output_file) = open_files_cla();
    let mut input_file = input_file;
    let mut key_file = key_file;
    let mut nonce_file = nonce_file;
    let mut output_file = output_file;

    let mut key = Vec::with_capacity(32);
    key_file.read_to_end(&mut key).expect("Cannot read the key in the file");
    if key.len() != 32 {
        panic!("The length of the key is wrong");
    }

    let mut nonce = Vec::with_capacity(32);
    nonce_file.read_to_end(&mut nonce).expect("Cannot read the nonce in the file");
    if nonce.len() != 12 {
        panic!("The length of the nonce is wrong");
    }

    let mut chacha20 = adiantum::chacha::ChaCha::new_chacha20(key.as_slice(), nonce.as_slice(), 1); //TODO is the cnt 0???
    let mut buf_in = [0u8; 64];
    let mut buf_out = [0u8; 64];

    while let Ok(n) = input_file.read(&mut buf_in) {
        if n == 0 {
            break;
        }
        chacha20.process(&buf_in[..n], &mut buf_out[..n]);
        output_file.write_all(&buf_out[..n]).expect("Cannot write to the output file");
    }
}

fn open_files_cla() -> (File, File, File, File) {
    let mut envs_it = env::args().skip(1); // skip the name of the program
    let inp_f = File::open(envs_it.next().expect("Input filename missing")).expect("Error opening the input file");
    let k_f = File::open(envs_it.next().expect("Key filename missing")).expect("Error opening the key file");
    let n_f= File::open(envs_it.next().expect("Nonce filename missing")).expect("Error opening the nonce file");
    let out_f= File::create(envs_it.next().expect("Output filename missing")).expect("Error opening the output file");

    (inp_f, k_f, n_f, out_f)
}