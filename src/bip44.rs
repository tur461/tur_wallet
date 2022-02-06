#[path = "utils.rs"] mod utils;

use std::collections::HashMap;
use hmac_sha512::HMAC as hmac512;
use utils::Util;

const MAC_KEY: &str = "Bitcoin seed";


struct Root_Key_Meta {
    version: HashMap<String, Vec<u8>>,
    depth_byte: Vec<u8>,
    parent_fingerprint: Vec<u8>,
    child_number_bytes: Vec<u8>,
    master_chain_code_bytes: Vec<u8>,
    master_secret_key_bytes: Vec<u8>,
}

impl Root_Key_Meta {
    
    pub fn get_root_key(&mut self, master_secret_key_L: &[u8], master_chain_code_R: &[u8]) -> String {
        self.master_chain_code_bytes = master_chain_code_R[..].to_vec();
        self.master_secret_key_bytes = [&[0u8; 1][..], &master_secret_key_L[..]].concat();
        let joined = [
            &self.version.get("MAIN_PVT").unwrap()[..],
            &self.depth_byte[..],
            &self.parent_fingerprint[..],
            &self.child_number_bytes[..],
            &self.master_chain_code_bytes[..],
            &self.master_secret_key_bytes[..]
        ].concat();
        bs58::encode(joined).with_check().into_string()
    }
}

pub struct BIP44 {
    root_key: String,
    master_private_key: String,
    root_meta: Root_Key_Meta,
}

impl BIP44 {
    pub fn new() -> BIP44 {
        let mut root_meta = Root_Key_Meta {
            version: HashMap::new(),
            depth_byte: [0u8; 1].to_vec(),
            parent_fingerprint: [0u8; 4].to_vec(),
            child_number_bytes: [0u8; 4].to_vec(),
            master_chain_code_bytes: [0u8; 32].to_vec(),
            master_secret_key_bytes: [0u8; 33].to_vec(),
        };
        root_meta.version.insert("MAIN_PUB".to_owned(), Util::hexstr2bytes("0488b21e"));
        root_meta.version.insert("MAIN_PVT".to_owned(), Util::hexstr2bytes("0488ade4"));
        root_meta.version.insert("TEST_PUB".to_owned(), Util::hexstr2bytes("043587cf"));
        root_meta.version.insert("TEST_PVT".to_owned(), Util::hexstr2bytes("04358394"));


        BIP44 {
            root_key: "".to_owned(),
            master_private_key: "".to_owned(),
            root_meta: root_meta
        }
    }

    pub fn generate_root_key_from_seed(&mut self, seed: &str) {
        let mac512 = hmac512::mac(Util::hexstr2bytes(seed), MAC_KEY.as_bytes());
        let master_secret_key_L = mac512[0..32].to_vec();
        let master_chain_code_R = mac512[32..].to_vec();
        self.root_key = self.root_meta.get_root_key(&master_secret_key_L, &master_chain_code_R);
    } 

    pub fn get_root_key(&self) -> String {
        self.root_key.to_string()
    }
}