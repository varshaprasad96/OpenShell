// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{CryptoContext, CryptoError, aead, jwt, pki, tls};
use openshell_openssl_poc::OpenSsl;
use std::{
    io::{Read, Write},
    sync::{Arc, Once},
};

fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        openshell_crypto::install_default_context(CryptoContext::new(Box::new(OpenSsl))).unwrap()
    });
}

#[test]
fn primitives_and_posture() {
    init();
    assert_eq!(
        openshell_crypto::sha256(b"abc").unwrap(),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    let mut digest = openshell_crypto::sha256_digest().unwrap();
    digest.update(b"a").unwrap();
    digest.update(b"bc").unwrap();
    assert_eq!(
        digest.finish().unwrap(),
        openshell_crypto::sha256(b"abc").unwrap()
    );
    assert_ne!(
        openshell_crypto::random_bytes::<32>().unwrap(),
        openshell_crypto::random_bytes::<32>().unwrap()
    );
    let context = openshell_crypto::default_context();
    let caps = context.verify_posture(false).unwrap();
    assert_eq!(caps.backend, "openssl-poc");
    assert!(caps.provider_version.unwrap().starts_with("OpenSSL 3."));
    assert_eq!(
        context.verify_posture(true),
        Err(CryptoError::UnsupportedPosture)
    );
}

#[test]
fn aead_compatibility_and_rejection() {
    init();
    // NIST AES-256-GCM empty-message vector: ciphertext consists only of the tag.
    let tag = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];
    assert_eq!(aead::open(&[0; 32], b"", &[0; 12], &tag).unwrap(), b"");
    for plain in [b"".as_slice(), b"credential-value"] {
        let sealed = aead::seal(&[7; 32], b"record-id", plain).unwrap();
        assert_eq!(sealed.ciphertext.len(), plain.len() + 16);
        assert_eq!(
            aead::open(&[7; 32], b"record-id", &sealed.nonce, &sealed.ciphertext).unwrap(),
            plain
        );
        assert_eq!(
            aead::open(&[8; 32], b"record-id", &sealed.nonce, &sealed.ciphertext),
            Err(CryptoError::Authentication)
        );
        assert_eq!(
            aead::open(&[7; 32], b"wrong-id", &sealed.nonce, &sealed.ciphertext),
            Err(CryptoError::Authentication)
        );
        let mut damaged = sealed.ciphertext.clone();
        damaged[0] ^= 1;
        assert_eq!(
            aead::open(&[7; 32], b"record-id", &sealed.nonce, &damaged),
            Err(CryptoError::Authentication)
        );
    }
    assert_eq!(
        aead::open(&[0; 32], b"", &[0; 12], &[0; 15]),
        Err(CryptoError::Authentication)
    );
}

#[test]
fn backend_owned_keys_and_certificates() {
    init();
    for alg in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
        &rcgen::PKCS_RSA_SHA256,
    ] {
        let key = pki::generate_keypair_for(alg).unwrap();
        let der = key.serialize_der().unwrap();
        let from_der = pki::KeyPair::from_pkcs8_der(&der).unwrap();
        let from_pem = pki::KeyPair::from_pem(&key.serialize_pem().unwrap()).unwrap();
        for imported in [&from_der, &from_pem] {
            assert_eq!(key.public_key_der(), imported.public_key_der());
            let cert = pki::self_signed(
                rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
                imported,
            )
            .unwrap();
            let x509 = openssl::x509::X509::from_der(cert.der()).unwrap();
            assert!(x509.verify(&x509.public_key().unwrap()).unwrap());
        }
    }
    assert!(pki::KeyPair::from_pkcs8_der(b"invalid key").is_err());
    assert!(pki::KeyPair::from_pem("invalid key").is_err());
}

#[test]
fn non_exportable_issuer_still_signs() {
    init();
    let issuer_key = OpenSsl.non_exportable_key().unwrap();
    assert!(issuer_key.serialize_der().is_err());
    assert!(issuer_key.serialize_pem().is_err());
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = pki::self_signed(ca_params, &issuer_key).unwrap();
    let leaf_key = pki::generate_keypair().unwrap();
    let leaf = pki::signed_by(
        rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
        &leaf_key,
        &ca,
        &issuer_key,
    )
    .unwrap();
    let public = openssl::pkey::PKey::public_key_from_der(&issuer_key.public_key_der()).unwrap();
    assert!(
        openssl::x509::X509::from_der(leaf.der())
            .unwrap()
            .verify(&public)
            .unwrap()
    );
}

#[test]
fn jwt_algorithms_and_claims_validation() {
    use jsonwebtoken::{
        Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::ErrorKind,
    };
    init();
    let claims = serde_json::json!({"sub":"sandbox", "iss":"gateway", "aud":"sandbox", "exp":4_000_000_000_u64});
    let mut keys = vec![(
        Algorithm::HS256,
        EncodingKey::from_secret(b"poc-test-secret"),
        DecodingKey::from_secret(b"poc-test-secret"),
    )];
    for (alg, key_alg) in [
        (Algorithm::EdDSA, &rcgen::PKCS_ED25519),
        (Algorithm::ES256, &rcgen::PKCS_ECDSA_P256_SHA256),
        (Algorithm::RS256, &rcgen::PKCS_RSA_SHA256),
    ] {
        let key = pki::generate_keypair_for(key_alg).unwrap();
        let private = key.serialize_pem().unwrap();
        let public = key.public_key_pem();
        let pair = match alg {
            Algorithm::EdDSA => (
                EncodingKey::from_ed_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_ed_pem(public.as_bytes()).unwrap(),
            ),
            Algorithm::ES256 => (
                EncodingKey::from_ec_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_ec_pem(public.as_bytes()).unwrap(),
            ),
            _ => (
                EncodingKey::from_rsa_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            ),
        };
        keys.push((alg, pair.0, pair.1));
    }
    for (alg, private, public) in keys {
        let token = jwt::encode(&Header::new(alg), &claims, &private).unwrap();
        let mut validation = Validation::new(alg);
        validation.set_issuer(&["gateway"]);
        validation.set_audience(&["sandbox"]);
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap()
                .claims,
            claims
        );
        let mut tampered = token.clone().into_bytes();
        let signature_start = tampered.iter().rposition(|b| *b == b'.').unwrap() + 1;
        tampered[signature_start] = if tampered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert_eq!(
            jwt::decode::<serde_json::Value>(&tampered, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidSignature
        );
        validation.set_issuer(&["wrong"]);
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidIssuer
        );
        validation.set_issuer(&["gateway"]);
        validation.set_audience(&["wrong"]);
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidAudience
        );
        validation.set_audience(&["sandbox"]);
        let expired =
            serde_json::json!({"sub":"sandbox", "iss":"gateway", "aud":"sandbox", "exp":1});
        let token = jwt::encode(&Header::new(alg), &expired, &private).unwrap();
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::ExpiredSignature
        );
    }
}

#[test]
fn tls13_handshake_and_application_data() {
    init();
    let pki::CertifiedKey { cert, key_pair } =
        pki::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = tls::client_builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = tls::server_builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der().unwrap()).into(),
        )
        .unwrap();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    for _ in 0..10 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    client.writer().write_all(b"openssl transport").unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server.read_tls(&mut wire.as_slice()).unwrap();
    server.process_new_packets().unwrap();
    let mut received = [0; 17];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"openssl transport");
}
