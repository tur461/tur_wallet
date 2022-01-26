use dotenv::dotenv;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::pbkdf2;

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    num::NonZeroU32
};
const BIP39_MAGIC_NUM: usize = 11;
const ENT_SZ_IDX: usize = 0;
const ENT_SZ: [usize; 5] = [128, 160, 192, 224, 256];

struct BIP39 {
    mnemonic: String,
    seed: String
}

impl BIP39 { 
    
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
    
    fn _pad_left(bin: &str, final_len: usize) -> String {
        let mut l = bin.len();
        let mut final_bin = "".to_owned();
        if l < final_len {
            l = final_len - l;
            for _i in 0..l {
                final_bin.push_str("0");
            }
        }
        final_bin.push_str(bin);
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
        for _i in 0..u32_parts {
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
    
    fn generate_seed(& mut self, wordlist_path: &str) {
        let mut passphrase: String = "".to_owned();
        println!("Enter a passphrase for extra level of security:");
        std::io::stdin().read_line(&mut passphrase).expect("some problem");
        self.mnemonic =  Self::_generate_mnemonic(wordlist_path);
        let mut salt = "mnemonic ".to_owned();
        salt.push_str(&passphrase.as_str());
        // let digest: MessageDigest = MessageDigest::sha256();
        let mut output: [u8; 32] = [0; 32];
        
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256, 
            NonZeroU32::new(2048).unwrap(), 
            &salt.as_bytes(),
          self.mnemonic.as_bytes(), 
          &mut output);
        self.seed = hex::encode(output);
    }
    
    fn _generate_mnemonic(wordlist_path: &str) -> String {
        let words = Self::_words_from_wordlist(wordlist_path);
        let entropy_with_checksum = Self::_get_entropy();
        let mut mnemonic_words = Vec::<&str>::new();
        let word_indexes = Self::_map_entropy2indexes(entropy_with_checksum.as_str());
        for i in word_indexes {
            mnemonic_words.push(words[i].as_str());
        }
        mnemonic_words.join(" ")
    }

    fn get_seed(&self) -> &str {
        self.seed.as_str()
    }

    fn get_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }


    
}

// struct BIP32 {
//     mnemonic: String,
//     seed: String
// }

// struct BIP44 {
//     mnemonic: String,
//     seed: String
// }

fn main() {
    println!("Starting...");
    dotenv().ok();
    let mut bip_39: BIP39 = BIP39 { 
        seed: String::from(""), 
        mnemonic: String::from("")
    };
    let path = std::env::var("EN_WORDLIST_PATH").unwrap();
    println!("generating mnemonic {}", path);
    bip_39.generate_seed(path.as_str());
    println!("\nmnemonic: {}\nseed: {:}\n", bip_39.get_mnemonic(), bip_39.get_seed())
}
