use thiserror::Error;

#[derive(Error, Debug)]
pub enum FileTransferError {
    #[error("magic header is not match")]
    InvalidHeader,
    #[error("hmac fail")]
    HmacVerifyFail,
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    KeyIvError(#[from] block_modes::InvalidKeyIvLength),
    #[error(transparent)]
    BlockModeError(#[from] block_modes::BlockModeError),
    #[error("generic error")]
    Generic,
}
