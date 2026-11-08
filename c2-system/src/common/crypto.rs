//! Cryptographic utilities for C2 communication.
//!
//! Provides end-to-end encryption, authentication, and key management.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{Aead as _, AeadCore as _, Payload},
    ChaCha20Poly1305, Key, Nonce as ChaChaNonce,
};
use sha2::{Digest, Sha256};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::{RngCore, thread_rng};
use ring::aead;
use ring::aead::UnboundKey;
use ring::aead::LessSafeKey;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Authentication tag mismatch")]
    AuthTagMismatch,
}

/// Encryption result
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Key pair for asymmetric encryption (placeholder for actual implementation)
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Session keys for symmetric encryption
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub encryption_key: [u8; 32],
    pub authentication_key: [u8; 32],
}

impl SessionKeys {
    /// Generate new random session keys
    pub fn generate() -> Self {
        let mut encryption_key = [0u8; 32];
        let mut authentication_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut encryption_key);
        rand::thread_rng().fill_bytes(&mut authentication_key);
        Self {
            encryption_key,
            authentication_key,
        }
    }

    /// Derive keys from a master secret using HKDF-like approach
    pub fn derive_from_master(master: &[u8], salt: &[u8], info: &[u8]) -> Self {
        // Simple key derivation - in production use proper HKDF
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(master);
        hasher.update(info);
        let derived = hasher.finalize();

        let mut encryption_key = [0u8; 32];
        let mut authentication_key = [0u8; 32];

        // Split derived key
        encryption_key.copy_from_slice(&derived[..32]);

        // Hash again for second key
        let mut hasher2 = Sha256::new();
        hasher2.update(&derived);
        hasher2.update(b"auth");
        let derived2 = hasher2.finalize();
        authentication_key.copy_from_slice(&derived2[..32]);

        Self {
            encryption_key,
            authentication_key,
        }
    }
}

/// Encryptor using AES-256-GCM
pub struct Aes256GcmEncryptor {
    cipher: Aes256Gcm,
}

impl Aes256GcmEncryptor {
    /// Create new encryptor with given key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Encrypt data with nonce
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            aad: aad.as_ref(),
            msg: plaintext,
        };
        self.cipher
            .encrypt(nonce_arr, payload)
            .map_err(|e| CryptoError::Encryption(e.to_string()))
    }

    /// Decrypt data with nonce
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            aad: aad.as_ref(),
            msg: ciphertext,
        };
        self.cipher
            .decrypt(nonce_arr, payload)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }

    /// Encrypt with random nonce
    pub fn encrypt_random(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<(Vec<u8>, [u8; 12])> {
        let nonce_arr = Aes256Gcm::generate_nonce(thread_rng());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_arr.as_ref());
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }
}

/// Encryptor using ChaCha20-Poly1305
pub struct ChaCha20Poly1305Encryptor {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Encryptor {
    /// Create new encryptor with given key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr = ChaCha20Poly1305::generate_nonce(thread_rng());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(nonce_arr.as_ref());
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);
        let payload = Payload {
            aad: aad.as_ref(),
            msg: plaintext,
        };
        self.cipher
            .encrypt(&nonce, payload)
            .map(|result| {
                let mut output = nonce_bytes.to_vec();
                output.extend_from_slice(result.as_ref());
                output
            })
            .map_err(|e| CryptoError::Encryption(e.to_string()))
    }

    /// Decrypt data (nonce is prepended to ciphertext)
    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        if data.len() < 24 {
            return Err(CryptoError::Decryption("Data too short".into()));
        }

        let nonce = ChaChaNonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let payload = Payload {
            aad: aad.as_ref(),
            msg: ciphertext,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

/// HMAC-based message authentication
pub fn compute_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(result.into_bytes().as_slice());
    tag
}

/// Verify HMAC
pub fn verify_hmac(key: &[u8], message: &[u8], tag: &[u8; 32]) -> bool {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

/// Derive a 32-byte key from a master key string.
pub fn derive_key(master: &str) -> [u8; 32] {
    Sha256::digest(master.as_bytes()).into()
}

/// Additional authenticated data for an envelope: headers that are sent in the clear.
fn envelope_aad(envelope: &super::message::MessageEnvelope) -> Vec<u8> {
    let mut aad = format!(
        "{}:{}:{}:",
        envelope.version, envelope.sequence, envelope.timestamp
    )
    .into_bytes();
    aad.extend_from_slice(&serde_json::to_vec(&envelope.channel).unwrap_or_default());
    aad
}

/// Encrypt and authenticate an envelope payload with the master key.
///
/// Layout: `encrypted_payload = nonce || ciphertext+tag`, `auth_tag = HMAC[..16]`.
pub fn seal_envelope(
    master_key: &str,
    envelope: &mut super::message::MessageEnvelope,
) -> CryptoResult<()> {
    let key = derive_key(master_key);
    let cipher = Aes256GcmEncryptor::new(&key);
    let nonce: [u8; 12] = rand::random();
    let ciphertext = cipher.encrypt(&nonce, &envelope.encrypted_payload, &envelope_aad(envelope))?;

    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&ciphertext);
    let tag = compute_hmac(&key, &payload);
    envelope.encrypted_payload = payload;
    envelope.auth_tag.copy_from_slice(&tag[..16]);
    Ok(())
}

/// Verify and decrypt an envelope payload.
pub fn open_envelope(
    master_key: &str,
    envelope: &super::message::MessageEnvelope,
) -> CryptoResult<Vec<u8>> {
    let key = derive_key(master_key);
    let expected = compute_hmac(&key, &envelope.encrypted_payload);
    let diff = expected[..16]
        .iter()
        .zip(envelope.auth_tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(CryptoError::AuthTagMismatch);
    }

    if envelope.encrypted_payload.len() < 12 + 16 {
        return Err(CryptoError::Decryption("Payload too short".into()));
    }
    let (nonce, ciphertext) = envelope.encrypted_payload.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().expect("12 bytes");
    let cipher = Aes256GcmEncryptor::new(&key);
    cipher.decrypt(&nonce, ciphertext, &envelope_aad(envelope))
}

/// Ring-based encryption (for compatibility)
pub struct RingEncryptor {
    key: LessSafeKey,
}

impl RingEncryptor {
    /// Create new encryptor with 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let unbound = UnboundKey::new(&aead::AES_256_GCM, key)
            .expect("32-byte key is valid for AES-256-GCM");
        Self {
            key: LessSafeKey::new(unbound),
        }
    }

    /// Encrypt with random nonce
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; aead::NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt
    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        if data.len() < aead::NONCE_LEN + 16 {
            return Err(CryptoError::Decryption("Data too short".into()));
        }

        let mut nonce_bytes = [0u8; aead::NONCE_LEN];
        nonce_bytes.copy_from_slice(&data[..aead::NONCE_LEN]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = data[aead::NONCE_LEN..].to_vec();
        self.key
            .open_in_place(nonce, aead::Aad::from(aad), &mut in_out)
            .map(|v| v.to_vec())
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

/// Key exchange using ECDH (simplified)
pub struct EcdhKeyExchange {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl EcdhKeyExchange {
    /// Create new key exchange instance
    pub fn new() -> CryptoResult<Self> {
        // In production, use proper ECDH library
        let mut private_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut private_key);

        // Derive public key (simplified - just hash of private)
        let mut hasher = Sha256::new();
        hasher.update(&private_key);
        let public_key = hasher.finalize().to_vec();

        Ok(Self {
            private_key: private_key.to_vec(),
            public_key,
        })
    }

    /// Get public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Derive shared secret from remote public key
    pub fn derive_shared_secret(&self, remote_public: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(&self.private_key);
        hasher.update(remote_public);
        Ok(hasher.finalize().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encryption() {
        let key = [0u8; 32];
        let encryptor = Aes256GcmEncryptor::new(&key);

        let plaintext = b"Hello, C2!";
        let nonce = [0u8; 12];
        let aad = b"header";

        let ciphertext = encryptor.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = encryptor.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha_encryption() {
        let key = [0u8; 32];
        let encryptor = ChaCha20Poly1305Encryptor::new(&key);

        let plaintext = b"Secret message";
        let aad = b"context";

        let ciphertext = encryptor.encrypt(plaintext, aad).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret_key";
        let message = b"Hello, world!";

        let tag = compute_hmac(key, message);
        assert!(verify_hmac(key, message, &tag));
        assert!(!verify_hmac(key, b"different message", &tag));
    }

    #[test]
    fn test_key_derivation() {
        let master = b"master_secret";
        let salt = b"unique_salt";
        let info = b"c2_session";

        let keys1 = SessionKeys::derive_from_master(master, salt, info);
        let keys2 = SessionKeys::derive_from_master(master, salt, info);

        assert_eq!(keys1.encryption_key, keys2.encryption_key);
        assert_eq!(keys1.authentication_key, keys2.authentication_key);
    }
}
