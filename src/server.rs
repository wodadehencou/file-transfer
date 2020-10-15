use super::constant::MAGIC_HEADER;
use super::encryption::decrypt;
use super::error::FileTransferError as Error;
use log::info;
use std::{
    io::{Read, Write},
    mem,
    net::TcpListener,
    time::Duration,
};

/// TODO:
/// Custom Frame
///    Total length is not bigger than 2048
///   Head(4) 0x91,0x16,0x10,0x83
///   Unique ID(8)
///   Total Frame length(4) BigEndian
///   Total seq number(2) BigEndian
///   Current seq number(2) BigEndian
///   Current cksum
///

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub fn new(addr: &str) -> Self {
        let listener = TcpListener::bind(addr).unwrap();
        Server { listener }
    }

    pub fn read(&self) -> Result<Vec<u8>, Error> {
        let (mut stream, addr) = self.listener.accept()?;
        info!("get a connection from {}", addr.to_string());
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;

        let mut header = [0; MAGIC_HEADER.len()];
        stream.read_exact(&mut header)?;
        if header != MAGIC_HEADER {
            return Err(Error::InvalidHeader);
        }

        let mut len_bytes = [0; mem::size_of::<u64>()];
        stream.read_exact(&mut len_bytes)?;
        let len = u64::from_be_bytes(len_bytes);
        if len > 1024 * 1024 * 1024 {
            return Err(Error::InvalidLength);
        }

        let mut data = vec![0; len as usize];
        stream.read_exact(data.as_mut_slice())?;

        stream.write(&MAGIC_HEADER)?;
        stream.write(&len_bytes)?;
        stream.write("OK".as_bytes())?;
        stream.flush()?;
        Ok(data)
    }

    pub fn receive_full(&self, password: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = self.read()?;
        info!("received cipher length is {}", cipher.len());
        decrypt(cipher.as_slice(), password)
    }
}
