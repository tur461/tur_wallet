mod bip39;

use dotenv::dotenv;
use bip39::BIP39;
// struct BIP32 {
// }

// struct BIP44 {
// }

fn main() {
    dotenv().ok();
    let mut bip_39: BIP39 = BIP39::new("", "");
    let path = std::env::var("EN_WORDLIST_PATH").unwrap();
    println!("generating mnemonic {}", path);
    bip_39.generate_seed(path.as_str());
    println!("\nmnemonic: {}\nseed: {:}\nseed len: {} bytes", bip_39.get_mnemonic(), bip_39.get_seed(), bip_39.get_seed().len()/2);
    //println!("mnemonic as bytes: {:?}", bip_39.get_mnemonic().as_bytes());
}
