mod client;
mod constant;
mod encryption;
mod error;
mod server;

use clap::{App, Arg};
use error::FileTransferError as Error;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
};

fn main() {
    env_logger::init();
    println!("Hello, world!");

    let matches = App::new("personal tcp file transfer application")
        .version("0.1")
        .about("send files from client to server using custom tcp protocol")
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .takes_value(true)
                .default_value("server"),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .default_value("file transfer"),
        )
        .arg(
            Arg::with_name("address")
                .help("server address to listen or client request address")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("filename")
                .help("file to store or file to send")
                .required(true)
                .index(2),
        )
        .get_matches();

    match matches.value_of("mode").unwrap_or_default() {
        "server" => server(
            matches.value_of("address").unwrap(),
            matches.value_of("filename").unwrap(),
            matches.value_of("password").unwrap(),
        )
        .unwrap(),
        "client" => client(
            matches.value_of("address").unwrap(),
            matches.value_of("filename").unwrap(),
            matches.value_of("password").unwrap(),
        )
        .unwrap(),
        _ => panic!("wrong mode"),
    }
}

const BUFFER_SIZE: usize = 256 * 1024;

fn client(server: &str, file: &str, password: &str) -> Result<(), Error> {
    let cli = client::Client::new(server);
    let password = get_password(password);

    let mut f = File::open(file)?;
    let mut buf = [0u8; BUFFER_SIZE];
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(err) => return Err(Error::from(err)),
        };
        cli.send_full(&buf[..n], &password)?;
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    Ok(())
}

fn server(addr: &str, file: &str, password: &str) -> Result<(), Error> {
    let svr = server::Server::new(addr);
    let password = get_password(password);

    let mut f = File::create(file)?;
    loop {
        let svr_receive = svr.receive_full(&password)?;
        let n = svr_receive.len();
        f.write_all(svr_receive.as_slice())?;
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    Ok(())
}

fn get_password<'a>(s: &'a str) -> [u8; 32] {
    let mut h = Sha256::default();
    h.update(s.as_bytes());
    let hash = h.finalize();
    hash.into()
}

#[cfg(test)]
mod test {

    use super::*;
    use std::{thread, time};

    #[test]
    fn test_loopback() {
        env_logger::init();
        println!("Hello, world!");

        let svr_password = get_password("password");
        let cli_password = svr_password;

        let svr_handler = thread::spawn(move || {
            let svr = server::Server::new("0.0.0.0:7777");
            let svr_receive = svr.receive_full(&svr_password).unwrap();
            println!(
                "server receive is {}",
                String::from_utf8(svr_receive).unwrap()
            );
        });

        thread::sleep(time::Duration::from_secs(1));

        let cli_handler = thread::spawn(move || {
            let cli = client::Client::new("127.0.0.1:7777");
            let msg = "client request".as_bytes();
            cli.send_full(msg, &cli_password).unwrap();
        });

        svr_handler.join().unwrap();
        cli_handler.join().unwrap();
    }
}
