use super::constant::MAGIC_HEADER;
use super::encryption::decrypt;
use super::error::FileTransferError as Error;
use std::{io::IoSlice, io::Read, io::Write, net::TcpListener};

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
        // println!("get a connection from {}", addr.to_string());
        let mut buf = [0; 2048];
        let n = stream.read(&mut buf)?;
        if !buf.starts_with(&MAGIC_HEADER) {
            return Err(Error::InvalidHeader);
        }
        // stream.write(&MAGIC_HEADER)?;
        // stream.write("OK".as_bytes())?;
        stream.write_vectored(&[IoSlice::new(&MAGIC_HEADER), IoSlice::new("OK".as_bytes())])?;
        stream.flush()?;
        Ok(Vec::from(&buf[MAGIC_HEADER.len()..n]))
    }

    pub fn receive_full(&self, password: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = self.read()?;
        decrypt(cipher.as_slice(), password)
    }
}
