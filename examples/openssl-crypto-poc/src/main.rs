// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{CryptoContext, install_default_context};
use openshell_openssl_poc::OpenSsl;

fn main() {
    install_default_context(CryptoContext::new(Box::new(OpenSsl))).unwrap();
    println!("{}", openssl::version::version());
    if std::env::args().any(|arg| arg == "--expect-unavailable") {
        assert!(openshell_crypto::sha256(b"abc").is_err());
        assert!(openshell_crypto::random_bytes::<32>().is_err());
        assert!(openshell_crypto::pki::generate_keypair().is_err());
        println!("required algorithms unavailable: failed closed without fallback");
    } else {
        openshell_crypto::sha256(b"abc").unwrap();
        openshell_crypto::random_bytes::<32>().unwrap();
        openshell_crypto::pki::generate_keypair().unwrap();
        println!("system OpenSSL primitives and key generation succeeded");
    }
}
