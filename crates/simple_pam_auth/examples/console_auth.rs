#![cfg(target_os = "linux")]

use std::{env::args, io::Write};

fn main() {

    let username = args().nth(1);

    let mut cb = simple_pam_auth::SimplePamAuthClientBuilder::new("login");
    if let Some(ref un) = username {
        cb = cb.username(un);
    }
    let mut client = cb
        .user_input_callback(|echoed, msg| {
            print!("{msg}");
            std::io::stdout().flush().expect("Failed to flush stdout");
            if echoed {
                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf).expect("Failed to read input");
                buf.trim_end().to_string()
            } else {
                rpassword::read_password().expect("Failed to read password from tty")
            }
        })
        .msg_callback(|is_error, msg| {
            if is_error {
                eprintln!("{msg}");
            } else {
                println!("{msg}");
            }
        })
        .build()
        .expect("Failed to build PAM client");

    match client.authenticate() {
        Ok(()) => println!("Authentication successful!"),
        Err(e) => println!("Authentication failed: {:?}", e),
    }
}