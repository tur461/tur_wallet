use dotenv::dotenv;
use sha2::{Sha256, Sha512, Digest};
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};

struct key_pair {
    private_key: String,
    public_key: String
}

impl key_pair {
    fn _get_pub_key(prv_key: &str) -> String {
        let ctx = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&hex::decode(prv_key).unwrap());
        let pub_key = PublicKey::from_secret_key(&ctx, &secret_key.unwrap());
        pub_key.to_string()
    }
    
    fn _get_prv_key(salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
    
    fn generate_key_pair(& mut self, salt: &str) {
        self.private_key = Self::_get_prv_key(salt);
        self.public_key = Self::_get_pub_key(self.private_key.as_str());
    }

    fn get_key_pair(&self) -> (&str, &str) {
        (self.private_key.as_str(), self.public_key.as_str())
    }

    fn get_public_key(&self) -> &str {
        self.public_key.as_str()
    }

    
}

fn main() {
    dotenv().ok();
    let mut k_pair: key_pair = key_pair{ private_key: String::from(""), public_key: String::from("") };
    k_pair.generate_key_pair(std::env::var("PRIVATE_KEY_SALT").unwrap().as_str());
    let pair = k_pair.get_key_pair();
    println!("private key: {}\npublic key: {}\n", pair.0, pair.1);
}
