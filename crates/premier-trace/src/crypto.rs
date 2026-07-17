use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use zeroize::Zeroize;

pub const KEY_FILE_ENV: &str = "PREMIER_TRACE_KEY_FILE";

pub struct EncryptionKey([u8; 32]);

impl Clone for EncryptionKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl EncryptionKey {
    pub fn from_file(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                bail!("trace key file must not be accessible by group or other users")
            }
        }
        let text = fs::read_to_string(path)?;
        Self::from_hex(text.trim())
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("trace encryption key must be exactly 64 hexadecimal characters")
        }
        let mut key = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            key[index] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        Ok(Self(key))
    }

    pub fn key_id(&self) -> String {
        let digest = Sha256::digest(self.0);
        format!("sha256:{}", hex_prefix(&digest, 16))
    }

    pub(crate) fn for_trace(&self, trace_id: &str) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"premier-trace-v1"), &self.0);
        let mut derived = [0_u8; 32];
        hkdf.expand(trace_id.as_bytes(), &mut derived)
            .map_err(|_| anyhow::anyhow!("trace key derivation failed"))?;
        Ok(Self(derived))
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<String> {
        let nonce: [u8; 24] = rand::random();
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("trace encryption failed"))?;
        let mut envelope = Vec::with_capacity(nonce.len() + encrypted.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(STANDARD.encode(envelope))
    }

    pub(crate) fn decrypt(&self, envelope: &str, aad: &[u8]) -> Result<Vec<u8>> {
        let bytes = STANDARD
            .decode(envelope)
            .context("invalid encrypted trace envelope")?;
        if bytes.len() < 24 + 16 {
            bail!("encrypted trace envelope is truncated")
        }
        let (nonce, encrypted) = bytes.split_at(24);
        XChaCha20Poly1305::new((&self.0).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: encrypted,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("trace decryption failed: wrong key or tampered data"))
    }
}

pub(crate) fn key_from_environment() -> Result<Option<EncryptionKey>> {
    std::env::var_os(KEY_FILE_ENV)
        .map(|path| EncryptionKey::from_file(Path::new(&path)))
        .transpose()
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_detects_wrong_keys_and_tampering() {
        let key = EncryptionKey::from_hex(&"11".repeat(32)).unwrap();
        let wrong = EncryptionKey::from_hex(&"22".repeat(32)).unwrap();
        let encrypted = key.encrypt(b"private", b"trace:aad").unwrap();
        assert_eq!(key.decrypt(&encrypted, b"trace:aad").unwrap(), b"private");
        assert!(wrong.decrypt(&encrypted, b"trace:aad").is_err());

        let mut bytes = STANDARD.decode(&encrypted).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(key.decrypt(&STANDARD.encode(bytes), b"trace:aad").is_err());
    }
}
