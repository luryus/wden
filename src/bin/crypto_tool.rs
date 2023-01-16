use std::io::Read;

use base64::prelude::*;
use clap::Parser;
use wden::bitwarden::cipher;
use wden::bitwarden::cipher::Cipher;

#[derive(Parser)]
struct Opts {
    #[arg(long)]
    username: String,

    #[arg(long)]
    password: String,

    #[arg(long)]
    symmetric_key_cipher: String,

    #[arg(long)]
    private_key_cipher: Option<String>,

    #[arg(long)]
    cipher: Option<String>,

    #[arg(long, default_value = "100000")]
    hash_iterations: u32,

    #[arg(long)]
    to_string: bool,

    #[arg(long)]
    encrypt: bool,
}

fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();

    let master_key =
        cipher::create_master_key(&opts.username, &opts.password, opts.hash_iterations);

    let symmetric_key_cipher = opts.symmetric_key_cipher.parse()?;
    let (enc_key, mac_key) = cipher::decrypt_symmetric_keys(&symmetric_key_cipher, &master_key)?;

    if !opts.encrypt && opts.cipher.is_none() {
        panic!("Either a cipher (to decrypt) or --encrypt must be specified");
    }

    if opts.encrypt {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut input_data = vec![];
        stdin.read_to_end(&mut input_data).unwrap();

        let res = Cipher::encrypt(&input_data, &enc_key, &mac_key).expect("Failed to encrypt");
        println!("{}", res.encode());
    } else {
        let cipher = opts.cipher.unwrap().parse::<Cipher>()?;
        let decrypted_cipher = if let Some(priv_key_cipher) = opts.private_key_cipher {
            let der_priv_key = priv_key_cipher
                .parse::<Cipher>()?
                .decrypt(&enc_key, &mac_key)?
                .into();
            cipher.decrypt_with_private_key(&der_priv_key)?
        } else {
            cipher.decrypt(&enc_key, &mac_key)?
        };

        println!("Decrypted cipher:\n{}", BASE64_STANDARD.encode(&decrypted_cipher));

        if opts.to_string {
            let cipher_str = String::from_utf8(decrypted_cipher).unwrap_or_default();
            println!("As string:\n{}", cipher_str);
        }
    }

    Ok(())
}
