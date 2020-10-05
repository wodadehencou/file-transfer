use super::constant::MAGIC_HEADER;
use super::encryption::encrypt;
use super::error::FileTransferError as Error;
use log::debug;
use std::io::Write;
use std::io::{IoSlice, Read};
use std::net::TcpStream;

pub struct Client {
    server_address: String,
}

impl Client {
    pub fn new(addr: &str) -> Self {
        Client {
            server_address: String::from(addr),
        }
    }

    pub fn send(&self, data: &[u8]) -> Result<(), Error> {
        let mut stream = TcpStream::connect(&self.server_address)?;
        // stream.write(&MAGIC_HEADER)?;
        // stream.write(data)?;
        stream.write_vectored(&[IoSlice::new(&MAGIC_HEADER), IoSlice::new(data)])?;
        stream.flush()?;
        let mut buf = [0; 16];
        let n = stream.read(&mut buf)?;
        debug!("get response from {}", stream.peer_addr()?);
        debug!("response is: \n{:X?}", &buf[0..n]);
        if &buf[0..MAGIC_HEADER.len()] != &MAGIC_HEADER {
            return Err(Error::InvalidHeader);
        }
        if buf[MAGIC_HEADER.len()..].starts_with("OK".as_bytes()) {
            return Ok(());
        }
        panic!("protocol not match")
    }

    pub fn send_full(&self, data: &[u8], password: &[u8]) -> Result<(), Error> {
        let cipher = encrypt(data, password)?;
        self.send(cipher.as_slice())?;
        Ok(())
    }
}
