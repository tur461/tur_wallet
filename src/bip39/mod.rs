use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::pbkdf2;

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    num::NonZeroU32
};

const SEED_BYTE_SIZE: usize = 64;
const BIP39_MAGIC_NUM: usize = 11;
const ENT_SZ_IDX: usize = 0; // default is 12 word mnemonic!
const ENT_SZ: [usize; 5] = [
    128,    // 12 word mnemonic 
    160,    // 15 ..
    192,    // 18 ..
    224,    // 21 ..
    256     // 24 ..
];

pub struct BIP39 {
    mnemonic: String,
    seed: String
}

impl BIP39 { 

    pub fn new(mn: &str, sd: &str) -> BIP39 {
        BIP39 {
            mnemonic: String::from(mn),
            seed: String::from(sd),
        }
    }
    
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
        num
    }
    
    fn _bin2hex(s: &str) -> String {
        let len = s.len();
        let mut hexed: String = "".to_owned();
        for i in (0..len).step_by(4) {
            let x = Self::_bin2int(&s[i..i+4]);
            match x {
                10 => hexed.push_str("a"),
                11 => hexed.push_str("b"),
                12 => hexed.push_str("c"),
                13 => hexed.push_str("d"),
                14 => hexed.push_str("e"),
                15 => hexed.push_str("f"),
                0|1|2|3|4|5|6|7|8|9 => hexed.push_str(format!("{}", x).as_str()),
                _ => (),
            };
        }
        hexed
    }
    
    fn _hex2bin(s: &str, bin_len: usize) -> String {
        let len = s.len();
        let mut bined: String = "".to_owned();
        for i in (0..len).step_by(2) {
            let slic = &s[i..i+2];
            let bin = format!("{:b}", Self::_bin2int(slic));
            let padded = Self::_lpad(bin.as_str(), bin_len);
           // println!("slice: {}\nbin: {}\npadded: {}", slic, bin, padded);
            bined.push_str(padded.as_str());
        }
        println!("\nbined: {}\ns: {}", bined, s);
        bined
    }

    fn _hexstr2bytes(s: &str) -> Vec<u8> {
        let len = s.len();
        let mut bytes: Vec<u8> = Vec::<u8>::new();
        for i in (0..len).step_by(2) {
            let slic = &s[i..i+2];
            let ss = u8::from_str_radix(slic, 16).unwrap();
            bytes.push(ss);
        }
        bytes
    }
    
    fn _lpad(bin: &str, final_len: usize) -> String {
        let mut l = bin.len();
        let mut final_bin = "".to_owned();
        if l < final_len {
            l = final_len - l;
            for _i in 0..l {
                final_bin.push_str("0");
            }
        } else if l > final_len {
            final_bin.push_str(&bin[0..final_len]);
        }
        final_bin.push_str(bin);
        return final_bin;
    }

    fn _get_normalised_ent(srand_str: &mut String) -> String {
        // we need to find sha256 of hex(entropy) not binary entropy string
        let hexed = Self::_bin2hex(&srand_str.as_str());
        let checksum_bit_len = ENT_SZ[ENT_SZ_IDX] / 32; // from bip39
        // get sha256 of un-normalised entropy
        let mut hasher = Sha256::new();
        hasher.update(Self::_hexstr2bytes(&hexed.as_str()));
        let result = hasher.finalize();
        // sha256 result is [u8] of 32 len -> 8x32 = 256 
        let result_first_byte_bin = Self::_lpad(format!("{:b}", result[0]).as_str(), 8);
      
        // now append first checksum_bit_len number of bits 
        // from sha256 of entropy, to the entropy string itself
        // to make its length divisible of bip39 magic number 11!
        srand_str.push_str(&result_first_byte_bin[0..checksum_bit_len]);
        srand_str.to_string()
    }
    
    fn _get_entropy() -> String {
        let u32_parts = ENT_SZ[ENT_SZ_IDX] / 32;
        let mut srand_str = "".to_owned();
        for _i in 0..u32_parts {
            let rnd_u32 = OsRng.next_u32();
            let bin_u32 = format!("{:b}", rnd_u32);
            // ensure binary is of 32 bits length!
            let padded = Self::_lpad(bin_u32.as_str(), 32);
            
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

    pub fn generate_seed(& mut self, wordlist_path: &str) {
        let mut passphrase: String = "".to_owned();
        println!("Enter a passphrase for extra level of security (press return key for none)):");
        std::io::stdin().read_line(&mut passphrase).expect("some problem");
        self.mnemonic =  Self::_generate_mnemonic(wordlist_path);
        let mut salt = "mnemonic".to_owned();
        salt.push_str(&passphrase.as_str());
        // let digest: MessageDigest = MessageDigest::sha256();
        let mut output = [0u8; SEED_BYTE_SIZE];
        
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512, 
            NonZeroU32::new(2048).unwrap(), 
            &salt.as_bytes(),
            self.mnemonic.as_bytes(), 
          &mut output);
        self.seed = hex::encode(output);
    }

    pub fn get_seed(&self) -> &str {
        self.seed.as_str()
    }

    pub fn get_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }
}