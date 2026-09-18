// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{CryptoContext, install_default_context};
use openshell_openssl_poc::OpenSsl;
use std::process::ExitCode;

fn main() -> ExitCode {
    install_default_context(CryptoContext::new(Box::new(OpenSsl))).unwrap();
    println!("{}", openssl::version::version());
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.iter().any(|arg| arg == "--require-fips") {
        // The contract deliberately has no verified FIPS state yet. Never
        // substitute an algorithm check or a property flag for attestation.
        if openshell_crypto::default_context()
            .verify_posture(true)
            .is_err()
        {
            eprintln!("FIPS posture is not verified; refusing a strict-FIPS claim");
            return ExitCode::from(2);
        }
    }
    if arguments.iter().any(|arg| arg == "--fips-report") {
        println!(
            "tls_provider_reports_fips={}",
            rustls_openssl::default_provider().fips()
        );
        println!(
            "fips_sha256_fetchable={}",
            openssl::md::Md::fetch(None, "SHA256", Some("fips=yes")).is_ok()
        );
        println!(
            "strict_posture_verified={}",
            openshell_crypto::default_context()
                .verify_posture(true)
                .is_ok()
        );
        println!("These are runtime diagnostics, not module or deployment validation.");
        return ExitCode::SUCCESS;
    }
    if arguments.iter().any(|arg| arg == "--expect-unavailable") {
        assert!(openshell_crypto::sha256(b"abc").is_err());
        assert!(openshell_crypto::random_bytes::<32>().is_err());
        for algorithm in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_RSA_SHA256,
            &rcgen::PKCS_ED25519,
        ] {
            assert!(openshell_crypto::pki::generate_keypair_for(algorithm).is_err());
        }
        println!("required algorithms unavailable: failed closed without fallback");
    } else {
        openshell_crypto::sha256(b"abc").unwrap();
        openshell_crypto::random_bytes::<32>().unwrap();
        openshell_crypto::pki::generate_keypair().unwrap();
        println!("system OpenSSL primitives and key generation succeeded");
    }
    ExitCode::SUCCESS
}
