// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental system-OpenSSL implementation of the existing crypto contract.
//! This is an interface PoC, not a production backend or a FIPS attestation.

use openshell_crypto::{
    Capabilities, CryptoBackend, CryptoError, Digest, FipsState, ProtocolBackend, aead::Sealed, pki,
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::Rsa,
    sign::Signer,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};

/// Uses the dynamically linked OpenSSL library's default library context.
pub struct OpenSsl;

struct Sha256(Hasher);
impl Digest for Sha256 {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0.update(bytes).map_err(|_| CryptoError::Operation)
    }
    fn finish(mut self: Box<Self>) -> Result<[u8; 32], CryptoError> {
        self.0
            .finish()
            .map_err(|_| CryptoError::Operation)?
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Operation)
    }
}

impl CryptoBackend for OpenSsl {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "openssl-poc",
            provider_version: Some(openssl::version::version()),
            fips: FipsState::NotVerified,
            primitives: &["RNG", "SHA-256", "AES-256-GCM"],
            key_algorithms: &["P-256", "P-384", "Ed25519", "RSA"],
        }
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        openssl::rand::rand_bytes(output).map_err(|_| CryptoError::Random)
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        Ok(Box::new(Sha256(
            Hasher::new(MessageDigest::sha256()).map_err(|_| CryptoError::Operation)?,
        )))
    }
    fn seal(&self, key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let mut nonce = [0; 12];
        self.fill_random(&mut nonce)?;
        let mut tag = [0; 16];
        let mut ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            key,
            Some(&nonce),
            aad,
            plaintext,
            &mut tag,
        )
        .map_err(|_| CryptoError::Operation)?;
        ciphertext.extend_from_slice(&tag);
        Ok(Sealed { nonce, ciphertext })
    }
    fn open(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let split = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(CryptoError::Authentication)?;
        let (data, tag) = ciphertext.split_at(split);
        decrypt_aead(Cipher::aes_256_gcm(), key, Some(nonce), aad, data, tag)
            .map_err(|_| CryptoError::Authentication)
    }
}

fn key_error(_: openssl::error::ErrorStack) -> rcgen::Error {
    rcgen::Error::RemoteKeyError
}

struct Key {
    inner: PKey<Private>,
    algorithm: &'static rcgen::SignatureAlgorithm,
    public: Vec<u8>,
    exportable: bool,
}

impl Key {
    fn wrap(
        inner: PKey<Private>,
        algorithm: &'static rcgen::SignatureAlgorithm,
        exportable: bool,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        let public = match inner.id() {
            Id::ED25519 => inner.raw_public_key().map_err(key_error)?,
            Id::EC => {
                let ec = inner.ec_key().map_err(key_error)?;
                let mut ctx = BigNumContext::new().map_err(key_error)?;
                ec.public_key()
                    .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                    .map_err(key_error)?
            }
            Id::RSA => inner
                .rsa()
                .map_err(key_error)?
                .public_key_to_der_pkcs1()
                .map_err(key_error)?,
            _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
        };
        pki::KeyPair::new(Box::new(Self {
            inner,
            algorithm,
            public,
            exportable,
        }))
    }
    fn import(inner: PKey<Private>) -> Result<pki::KeyPair, rcgen::Error> {
        let algorithm = match inner.id() {
            Id::ED25519 => &rcgen::PKCS_ED25519,
            Id::RSA => &rcgen::PKCS_RSA_SHA256,
            Id::EC => match inner.ec_key().map_err(key_error)?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => &rcgen::PKCS_ECDSA_P256_SHA256,
                Some(Nid::SECP384R1) => &rcgen::PKCS_ECDSA_P384_SHA384,
                _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
            },
            _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
        };
        Self::wrap(inner, algorithm, true)
    }
}

impl pki::SigningKey for Key {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
    fn public_key_raw(&self) -> &[u8] {
        &self.public
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signer = if self.inner.id() == Id::ED25519 {
            Signer::new_without_digest(&self.inner)
        } else {
            let digest = if self.algorithm == &rcgen::PKCS_ECDSA_P384_SHA384
                || self.algorithm == &rcgen::PKCS_RSA_SHA384
            {
                MessageDigest::sha384()
            } else if self.algorithm == &rcgen::PKCS_RSA_SHA512 {
                MessageDigest::sha512()
            } else {
                MessageDigest::sha256()
            };
            Signer::new(digest, &self.inner)
        }
        .map_err(key_error)?;
        signer.sign_oneshot_to_vec(message).map_err(key_error)
    }
    fn export_pkcs8_der(&self) -> Result<Vec<u8>, rcgen::Error> {
        if !self.exportable {
            return Err(rcgen::Error::RemoteKeyError);
        }
        self.inner.private_key_to_pkcs8().map_err(key_error)
    }
}

impl OpenSsl {
    /// Software-enforced non-exportable key for exercising the ownership contract.
    /// This does not claim hardware-backed storage or protection from memory access.
    pub fn non_exportable_key(&self) -> Result<pki::KeyPair, rcgen::Error> {
        Key::wrap(
            self.generate(&rcgen::PKCS_ECDSA_P256_SHA256)?,
            &rcgen::PKCS_ECDSA_P256_SHA256,
            false,
        )
    }
    fn generate(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<PKey<Private>, rcgen::Error> {
        if algorithm == &rcgen::PKCS_ED25519 {
            return PKey::generate_ed25519().map_err(key_error);
        }
        if [
            &rcgen::PKCS_RSA_SHA256,
            &rcgen::PKCS_RSA_SHA384,
            &rcgen::PKCS_RSA_SHA512,
        ]
        .contains(&algorithm)
        {
            return PKey::from_rsa(Rsa::generate(2048).map_err(key_error)?).map_err(key_error);
        }
        let curve = if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
            Nid::X9_62_PRIME256V1
        } else if algorithm == &rcgen::PKCS_ECDSA_P384_SHA384 {
            Nid::SECP384R1
        } else {
            return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
        };
        let group = EcGroup::from_curve_name(curve).map_err(key_error)?;
        PKey::from_ec_key(EcKey::generate(&group).map_err(key_error)?).map_err(key_error)
    }
}

impl ProtocolBackend for OpenSsl {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        rustls_openssl::default_provider()
    }
    fn generate_keypair(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        Key::wrap(self.generate(algorithm)?, algorithm, true)
    }
    fn import_keypair_pem(&self, pem: &str) -> Result<pki::KeyPair, rcgen::Error> {
        Key::import(PKey::private_key_from_pem(pem.as_bytes()).map_err(key_error)?)
    }
    fn import_keypair_der(&self, der: &[u8]) -> Result<pki::KeyPair, rcgen::Error> {
        Key::import(PKey::private_key_from_pkcs8(der).map_err(key_error)?)
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        &jsonwebtoken_openssl::DEFAULT_PROVIDER
    }
}
