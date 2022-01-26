use dotenv::dotenv;
use sha2::{Sha256, Sha512, Digest};
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use rand::rngs::OsRng;
use rand::RngCore;

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

use atoi::atoi;

const BIP39_MAGIC_NUM: usize = 11;
const ENT_SZ_IDX: usize = 0;
const ENT_SZ: [usize; 5] = [128, 160, 192, 224, 256];

struct BIP_39 {
    mnemonic: String,
    seed: String
}

impl BIP_39 { 
    
    fn _words_from_wordlist(path: &str) -> Vec<String> {
        let file = File::open(path).expect("no such file");
        let buf = BufReader::new(file);
        buf.lines()
            .map(|l| l.expect("Could not parse line"))
            .collect()
    }

    fn _bin2int(bin: &str) -> usize {
        let mut num: usize = 0;
        let mut i = 0;
        let bits = bin.chars().rev().collect::<String>();
        for b in bits.chars() {
            num = num + (usize::pow(2, i) * b.to_string().parse::<usize>().unwrap());
            i += 1
        }
        //println!("\nbin: {} num: {}\n\n", bin, num);
        num
    }
    
    fn _pad_left(u32_bin: &str, final_len: usize) -> String {
        let mut l = u32_bin.len();
        let mut final_bin = "".to_owned();
        if l < final_len {
            l = final_len - l;
            for i in 0..l {
                final_bin.push_str("0");
            }
        }
        final_bin.push_str(u32_bin);
        return final_bin;
    }

    fn _get_normalised_ent(srand_str: &mut String) -> String {
        let checksum_bit_len = ENT_SZ[ENT_SZ_IDX] / 32; // from bip39
        // get sha256 of un-normalised entropy
        let mut hasher = Sha256::new();
        hasher.update(srand_str.as_bytes());
        let result = hasher.finalize();
        // sha256 result is [u8] of 32 len -> 8x32 = 256 
        let result_last_byte_bin = Self::_pad_left(format!("{:b}", result[31]).as_str(), 8);
        // now append last checksum_bit_len number of bits 
        // from sha256 of entropy, to the entropy string itself
        // to make its length divisible of bip39 magic number 11! 
        srand_str.push_str(&result_last_byte_bin[8-checksum_bit_len..]);
        srand_str.to_string()
    }
    
    fn _get_entropy() -> String {
        let u32_parts = ENT_SZ[ENT_SZ_IDX] / 32;
        let mut srand_str = "".to_owned();
        for i in 0..u32_parts {
            let rnd_u32 = OsRng.next_u32();
            let bin_u32 = format!("{:b}", rnd_u32);
            // ensure binary is of 32 bits length!
            let padded = Self::_pad_left(bin_u32.as_str(), 32);
            // println!("\n[i]: {},\n\tu32: {}\n\tbin   : {}\n\tpadded: {}\n", i, rnd_u32, bin_u32, padded);
            srand_str.push_str(padded.as_str());
        }
        srand_str = Self::_get_normalised_ent(&mut srand_str);
        srand_str
    }

    fn _map_entropy2indexes(ent_w_c: &str) -> Vec<usize> {
        ent_w_c.chars()
        .collect::<Vec<char>>()
        .chunks(BIP39_MAGIC_NUM)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .iter()
        .map(|s| Self::_bin2int(s))
        .collect()
    }
    
    // fn generate_seed(& mut self) {
        
    // }
    
    fn generate_mnemonic(& mut self, wordlist_path: &str) {
        let words = Self::_words_from_wordlist(wordlist_path);
        let entropy_with_checksum = Self::_get_entropy();
        let mut mnemonic_words = Vec::<&str>::new();
        let word_indexes = Self::_map_entropy2indexes(entropy_with_checksum.as_str());
        for i in word_indexes {
            mnemonic_words.push(words[i].as_str());
        }
        self.mnemonic =  mnemonic_words.join(" ");
    }

    fn get_seed(&self) -> &str {
        self.seed.as_str()
    }

    fn get_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }


    
}

struct BIP_32 {
    mnemonic: String,
    seed: String
}

struct BIP_44 {
    mnemonic: String,
    seed: String
}

fn main() {
    dotenv().ok();
    let mut bip_39: BIP_39 = BIP_39 { 
        seed: String::from(""), 
        mnemonic: String::from("")
    };
    let path = std::env::var("EN_WORDLIST_PATH").unwrap();
    
    bip_39.generate_mnemonic(path.as_str());
    println!("mnemonic: {:?}", bip_39.get_mnemonic());
}
