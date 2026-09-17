# OpenSSL crypto interface proof of concept

This standalone example implements the existing `openshell-crypto` contracts with
system OpenSSL. It does not select OpenSSL for application binaries. A separate
Cargo workspace disables the facade's AWS-LC default feature without inheriting
the application's backend selection.

Run with Rust, a C compiler, pkg-config and OpenSSL 3 development libraries:

```shell
bash examples/openssl-crypto-poc/validate.sh
```

The script sets `OPENSSL_NO_VENDOR=1` and `OPENSSL_STATIC=0`, runs formatting,
Clippy and contract tests, rejects AWS-LC, Ring and vendored OpenSSL dependencies,
inspects dynamic linkage, and tests unavailable-provider failure in a fresh
process. Dependency and linkage reports go into the ignored target directory.

On macOS, OpenSSL can come from Homebrew. On Linux it comes from the distribution's
development package. Rust bindings and adapters compile into the binary;
OpenSSL's `libcrypto` and `libssl` remain shared libraries. Runtime loading of
OpenSSL provider modules is separate from this library linkage.

For Linux validation from macOS:

```shell
docker run --rm \
  -v "$PWD:/src:ro" \
  -w /src/examples/openssl-crypto-poc \
  -e CARGO_TARGET_DIR=/tmp/openssl-poc-target \
  -e RUSTUP_TOOLCHAIN=1.94.0 \
  rust:1.94-bookworm \
  bash -c 'rustup component add clippy rustfmt && bash validate.sh'
```

## Contract coverage

- RNG, incremental SHA-256 and a SHA-256 known-answer vector.
- AES-256-GCM with the existing nonce/appended-tag envelope, a known-answer
  vector, and wrong-key, wrong-AAD, truncated and modified ciphertext rejection.
- OpenSSL-owned P-256, P-384, Ed25519 and RSA keys; PKCS#8/PEM import and export;
  and certificate signatures checked through OpenSSL's X.509 API.
- A software-enforced non-exportable issuer that still signs certificates.
  This demonstrates ownership, not hardware-backed key protection.
- HS256, ES256, RS256 and EdDSA JWT signing and verification through the facade,
  including invalid signatures, issuer, audience and expiry rejection.
- A Rustls TLS 1.3 handshake and encrypted application data using OpenSSL for
  TLS cryptography and certificate verification.
- Configuration making OpenSSL algorithm fetches deliberately unsatisfiable:
  RNG, digest and key generation return errors without backend fallback.

The adapters are `rustls-openssl` 0.4.1 and `jsonwebtoken-openssl` 1.0.0. The
latter supports jsonwebtoken 10; its version 2 targets jsonwebtoken 11.

## Findings and remaining work

The backend-owned key and protocol contracts support OpenSSL without changing
the facade's traits. OpenSSL resources stay in the key object; rcgen encodes
certificates and delegates signing.

The PoC enables rcgen's optional `x509-parser` feature only in the MITM proxy
crate, which imports persisted CA certificates. The facade does not need it.
This removes Ring from this standalone PoC while preserving the application's
CA-import API. The full application still pulls Ring through that parser;
removing it requires a different import path or an upstream dependency change.

Other limitations remain:

- rcgen 0.13.2 exposes its P-521 signature descriptor only with AWS-LC enabled.
  P-521 is omitted here despite OpenSSL supporting it. A follow-up needs upstream
  descriptor availability or a different protocol representation.
- Strict FIPS requests still fail closed through the existing posture API.
  System OpenSSL linkage is not FIPS attestation. RHEL validation must check
  provider packages, configuration, crypto policy and the supported environment.
- TLS-provider construction is infallible in the current trait. Production
  startup needs a policy for reporting configuration failures. Some upstream
  adapter helpers panic on OpenSSL failure; the primitive negative test does not
  attest all adapter failure paths.
- JWT still uses jsonwebtoken's global provider. Install the context before JWT
  initialization. The PoC does not replace another installed JWT provider.
- Whole-gateway operation, dependency-owned TLS, packaging, RHEL policy, and
  FIPS restrictions on existing algorithms need separate integration work.

Run the example's validation script explicitly: it is intentionally outside the
normal workspace test task. This is an experiment, not a production backend.

## Validation results

The validation script passed on macOS ARM64 with Homebrew OpenSSL 3.6.3 and on
Debian Bookworm ARM64 with distribution OpenSSL 3.0.18 (Rust 1.94 container).
Both runs passed all six contract tests, Clippy, the no-AWS-LC/no-Ring dependency
check, dynamic-link inspection and unavailable-provider negative checks.
The Linux container does not validate RHEL or a FIPS-enabled host.
