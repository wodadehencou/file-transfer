use super::error::FileTransferError as Error;
use aes::block_cipher::generic_array::typenum::Unsigned;
use aes::{Aes128, NewBlockCipher};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::{Hmac, Mac, NewMac};
use rand::Rng;
use sha2::Sha256;

// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let iv_size = <Aes128Cbc as BlockMode<Aes128, Pkcs7>>::IvSize::USIZE;
    let key_size = <Aes128 as NewBlockCipher>::KeySize::USIZE;

    let iv = new_iv();
    let cipher = Aes128Cbc::new_var(&key[..key_size], &iv[..iv_size])?;

    let cipher_text = cipher.encrypt_vec(&data);
    let mut full_cipher = Vec::from(&iv[..]);
    full_cipher.extend(cipher_text);

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(key).expect("HMAC can take key of any size");
    mac.update(full_cipher.as_slice());

    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let mac_result = mac.finalize();
    // To get underlying array use `into_bytes` method, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `Output`
    let mac_bytes = mac_result.into_bytes();
    full_cipher.extend_from_slice(mac_bytes.as_slice());

    Ok(full_cipher)
}

pub fn decrypt(full_cipher: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let iv_size = <Aes128Cbc as BlockMode<Aes128, Pkcs7>>::IvSize::USIZE;
    let hmac_size = <HmacSha256 as Mac>::OutputSize::USIZE;
    let key_size = <Aes128 as NewBlockCipher>::KeySize::USIZE;

    let iv = &full_cipher[0..iv_size];
    let cipher_text = &full_cipher[iv_size..full_cipher.len() - hmac_size];
    let mac_input = &full_cipher[0..full_cipher.len() - hmac_size];
    let mac_act = &full_cipher[full_cipher.len() - hmac_size..];

    let cipher = Aes128Cbc::new_var(&key[..key_size], &iv[..iv_size])?;
    let plain_text = cipher.decrypt_vec(cipher_text)?;

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(key).expect("HMAC can take key of any size");
    mac.update(mac_input);

    // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    mac.verify(mac_act).unwrap();
    Ok(plain_text)
}

fn new_iv() -> [u8; 16] {
    rand::thread_rng().gen::<[u8; 16]>()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ende() {
        let key = rand::thread_rng().gen::<[u8; 16]>();
        let plain = rand::thread_rng().gen::<[u8; 30]>();
        let cipher = encrypt(&plain, &key).unwrap();
        let plain_act = decrypt(cipher.as_slice(), &key).unwrap();
        assert_eq!(&plain, plain_act.as_slice());
    }
}
