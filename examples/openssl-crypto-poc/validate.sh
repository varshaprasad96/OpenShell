#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"
export OPENSSL_NO_VENDOR=1
export OPENSSL_STATIC=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
cargo tree --locked --edges normal,build > "$CARGO_TARGET_DIR/poc-dependency-tree.txt"
if grep -Eq '(^|[^[:alnum:]_-])(aws-lc-rs|aws-lc-sys|aws-lc-fips-sys|ring|openssl-src) v' "$CARGO_TARGET_DIR/poc-dependency-tree.txt"; then
    echo "Unexpected AWS-LC, Ring, or vendored OpenSSL dependency" >&2
    exit 1
fi
binary="$CARGO_TARGET_DIR/debug/openshell-openssl-poc"
case "$(uname -s)" in
    Darwin) otool -L "$binary" > "$CARGO_TARGET_DIR/poc-linked-libraries.txt" ;;
    Linux) ldd "$binary" > "$CARGO_TARGET_DIR/poc-linked-libraries.txt" ;;
    *) echo "Unsupported validation platform" >&2; exit 1 ;;
esac
cat "$CARGO_TARGET_DIR/poc-linked-libraries.txt"
grep -Eq 'libcrypto[.].*(dylib|so)|libcrypto[.]so' "$CARGO_TARGET_DIR/poc-linked-libraries.txt"
"$binary"
OPENSSL_CONF="$PWD/unavailable.cnf" "$binary" --expect-unavailable
