use wden::bitwarden::cipher;
use wden::bitwarden::cipher::Cipher;
use clap::Parser;

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    username: String,

    #[clap(long)]
    password: String,

    #[clap(long)]
    symmetric_key_cipher: String,

    #[clap(long)]
    private_key_cipher: Option<String>,

    #[clap(long)]
    cipher: String,

    #[clap(long, default_value = "100000")]
    hash_iterations: u32,

    #[clap(long)]
    to_string: bool,
}

fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();

    let master_key =
        cipher::create_master_key(&opts.username, &opts.password, opts.hash_iterations);

    let symmetric_key_cipher = opts.symmetric_key_cipher.parse()?;
    let (enc_key, mac_key) = cipher::decrypt_symmetric_keys(&symmetric_key_cipher, &master_key)?;

    let cipher = opts.cipher.parse::<Cipher>()?;
    let decrypted_cipher = if let Some(priv_key_cipher) = opts.private_key_cipher {
        let der_priv_key = priv_key_cipher
            .parse::<Cipher>()?
            .decrypt(&enc_key, &mac_key)?
            .into();
        cipher.decrypt_with_private_key(&der_priv_key)?
    } else {
        cipher.decrypt(&enc_key, &mac_key)?
    };

    println!("Decrypted cipher:\n{}", base64::encode(&decrypted_cipher));

    if opts.to_string {
        let cipher_str = String::from_utf8(decrypted_cipher).unwrap_or_default();
        println!("As string:\n{}", cipher_str);
    }

    Ok(())
}
