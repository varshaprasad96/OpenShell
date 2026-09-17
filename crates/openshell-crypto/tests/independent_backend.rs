// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract probes, deliberately not real cryptography. Also run without any
//! default backend to detect accidental reliance on compiled AWS-LC operations.
use openshell_crypto::{
    Capabilities, CryptoBackend, CryptoContext, CryptoError, Digest, FipsState, ProtocolBackend,
    aead, pki,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

static SIGNS: AtomicUsize = AtomicUsize::new(0);
static IMPORTS: AtomicUsize = AtomicUsize::new(0);
struct Key {
    exportable: bool,
    drops: Arc<AtomicUsize>,
}
impl Drop for Key {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl pki::SigningKey for Key {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
    fn public_key_raw(&self) -> &[u8] {
        &[7; 32]
    }
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        SIGNS.fetch_add(1, Ordering::SeqCst);
        Ok(vec![9; 64])
    }
    fn export_pkcs8_der(&self) -> Result<Vec<u8>, rcgen::Error> {
        if self.exportable {
            Ok(b"test backend key".to_vec())
        } else {
            Err(rcgen::Error::RemoteKeyError)
        }
    }
}
struct TestDigest([u8; 32]);
impl Digest for TestDigest {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        for (index, byte) in bytes.iter().enumerate() {
            self.0[index % 32] ^= byte;
        }
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<[u8; 32], CryptoError> {
        Ok(self.0)
    }
}
struct Backend;
impl CryptoBackend for Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "test-only",
            provider_version: None,
            fips: FipsState::NotVerified,
            primitives: &[],
            key_algorithms: &[],
        }
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Random)
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        Ok(Box::new(TestDigest([0; 32])))
    }
    fn seal(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<aead::Sealed, CryptoError> {
        // Opaque sentinel layout verifies dispatch; it is NOT an encryption scheme.
        let mut ciphertext = key.to_vec();
        ciphertext.extend_from_slice(aad);
        ciphertext.extend_from_slice(plaintext);
        Ok(aead::Sealed {
            nonce: [42; 12],
            ciphertext,
        })
    }
    fn open(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let prefix = [key.as_slice(), aad].concat();
        if nonce != &[42; 12] || !ciphertext.starts_with(&prefix) {
            return Err(CryptoError::Authentication);
        }
        Ok(ciphertext[prefix.len()..].to_vec())
    }
}
impl ProtocolBackend for Backend {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        panic!("TLS is not used by this contract probe")
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        panic!("JWT is not used by this contract probe")
    }
    fn generate_keypair(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        if algorithm != &rcgen::PKCS_ED25519 {
            return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
        }
        pki::KeyPair::new(Box::new(Key {
            exportable: true,
            drops: Arc::default(),
        }))
    }
    fn import_keypair_der(&self, der: &[u8]) -> Result<pki::KeyPair, rcgen::Error> {
        if der != b"test backend key" {
            return Err(rcgen::Error::RemoteKeyError);
        }
        IMPORTS.fetch_add(1, Ordering::SeqCst);
        self.generate_keypair(&rcgen::PKCS_ED25519)
    }
    fn import_keypair_pem(&self, value: &str) -> Result<pki::KeyPair, rcgen::Error> {
        let parsed = pem::parse(value).map_err(|_| rcgen::Error::RemoteKeyError)?;
        self.import_keypair_der(parsed.contents())
    }
}
#[test]
fn independent_backend_controls_envelopes_and_the_entire_key_lifecycle() {
    openshell_crypto::install_default_context(CryptoContext::new(Box::new(Backend))).unwrap();
    let sealed = aead::seal(&[1; 32], b"record", b"payload").unwrap();
    assert_eq!(sealed.nonce, [42; 12]);
    assert_eq!(
        aead::open(&[1; 32], b"record", &sealed.nonce, &sealed.ciphertext).unwrap(),
        b"payload"
    );
    assert_eq!(
        aead::open(&[1; 32], b"wrong", &sealed.nonce, &sealed.ciphertext),
        Err(CryptoError::Authentication)
    );
    let key = pki::generate_jwt_keypair().unwrap();
    let der = key.serialize_der().unwrap();
    let pem = key.serialize_pem().unwrap();
    let imported = pki::KeyPair::from_pem(&pem).unwrap();
    let imported_der = pki::KeyPair::from_pkcs8_der(&der).unwrap();
    assert_eq!(IMPORTS.load(Ordering::SeqCst), 2);
    assert_eq!(imported.public_key_der(), imported_der.public_key_der());
    let issuer = pki::self_signed(rcgen::CertificateParams::default(), &imported).unwrap();
    pki::signed_by(
        rcgen::CertificateParams::default(),
        &key,
        &issuer,
        &imported,
    )
    .unwrap();
    assert_eq!(SIGNS.load(Ordering::SeqCst), 2);
    let drops = Arc::new(AtomicUsize::new(0));
    let non_exportable = pki::KeyPair::new(Box::new(Key {
        exportable: false,
        drops: drops.clone(),
    }))
    .unwrap();
    assert!(non_exportable.serialize_der().is_err());
    assert!(non_exportable.serialize_pem().is_err());
    pki::self_signed(rcgen::CertificateParams::default(), &non_exportable).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(non_exportable);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
