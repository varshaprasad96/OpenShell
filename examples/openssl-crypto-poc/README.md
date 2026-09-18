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
- Persisted CA import and leaf issuance through the backend-free parser.
- A software-enforced non-exportable issuer that still signs certificates.
  This demonstrates ownership, not hardware-backed key protection.
- HS256, ES256, RS256 and EdDSA JWT signing and verification through the facade,
  including invalid signatures, issuer, audience and expiry rejection.
- A Rustls TLS 1.3 handshake and encrypted application data using OpenSSL for
  TLS cryptography and certificate verification.
- Configuration making OpenSSL algorithm fetches deliberately unsatisfiable:
  RNG, digest and EVP key generation return errors without backend fallback.

The adapters are `rustls-openssl` 0.4.1 and `jsonwebtoken-openssl` 1.0.0. The
latter supports jsonwebtoken 10; its version 2 targets jsonwebtoken 11.

## Findings and remaining work

The backend-owned key and protocol contracts support OpenSSL without changing
the facade's traits. OpenSSL resources stay in the key object; rcgen encodes
certificates and delegates signing.

CA import uses the facade's `pki::issuer_from_der` helper with `x509-parser`
without cryptographic verification features. rcgen 0.14.10 continues certificate
encoding and delegates signing to backend-owned keys. Its own `x509-parser`
feature stays disabled because it also compiles CSR verification requiring
AWS-LC or Ring. The CA-import contract test parses a persisted CA, signs a leaf
with OpenSSL, and verifies its signature and issuer name through OpenSSL.
This removes the parser dependency blocker without vendoring or patching rcgen.

Other limitations remain:

- rcgen 0.14.10 exposes its P-521 signature descriptor only with AWS-LC enabled.
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

The refreshed PoC passes all eight contract tests on macOS ARM64 with Homebrew
OpenSSL 3.6.3, including persisted CA import. Formatting, Clippy, dependency checks,
dynamic-link inspection, and unavailable-provider negative checks also pass.
The standalone dependency graph contains no AWS-LC, Ring, or vendored OpenSSL.

`--fips-report` reports TLS FIPS posture, SHA-256 availability with `fips=yes`,
and the facade's strict posture result. On this development host all three are
false; only the default OpenSSL provider is active and no FIPS module is installed.
`--require-fips` exits with status 2, as required for an unverified backend.
These diagnostics are not module validation or deployment attestation.

The earlier version passed on Debian Bookworm ARM64 with distribution OpenSSL
3.0.18. The refreshed parser version has not been rerun on Linux because the local
Docker daemon is unresponsive. No RHEL FIPS environment has been validated.
