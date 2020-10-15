use log::info;

use super::constant::MAGIC_HEADER;
use super::encryption::encrypt;
use super::error::FileTransferError as Error;
use std::net::TcpStream;
use std::{io::Read, mem};
use std::{io::Write, time::Duration};

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

        // write magic header
        stream.write(&MAGIC_HEADER)?;

        // write data size
        let len = data.len() as u64;
        stream.write(&len.to_be_bytes())?;

        // write data
        stream.write(data)?;

        stream.flush()?;

        stream.set_read_timeout(Some(Duration::from_secs(1)))?;

        let mut exp_header = [0; MAGIC_HEADER.len()];
        stream.read_exact(&mut exp_header)?;
        if exp_header != MAGIC_HEADER {
            return Err(Error::InvalidHeader);
        }
        info!("get response from {}", stream.peer_addr()?);

        let mut exp_len = [0; mem::size_of::<u64>()];
        stream.read_exact(&mut exp_len)?;
        if u64::from_be_bytes(exp_len) != len {
            return Err(Error::InvalidLength);
        }

        let mut exp_ok = [0; 2];
        stream.read_exact(&mut exp_ok)?;
        if exp_ok == "OK".as_bytes() {
            return Ok(());
        }
        return Err(Error::Generic);
    }

    pub fn send_full(&self, data: &[u8], password: &[u8]) -> Result<(), Error> {
        let cipher = encrypt(data, password)?;
        info!(
            "client ready to send encrypted data length {}",
            cipher.len()
        );
        self.send(cipher.as_slice())?;
        Ok(())
    }
}
