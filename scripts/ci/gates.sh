#!/bin/sh
# rustydns member gate entrypoint (AQ-157).
#
# tooling/dev-push.sh runs exactly this file -- executable, at this exact
# path -- and advances `development` only on exit 0. "No gates" is not
# "gates passed"; a missing tool fails the run rather than skipping it.
#
# CI parity: .github/workflows/ci.yml, `test` job ("This job IS the MSRV
# gate", ci.yml:35-41). The gates below run that job's step sequence
# (Format check ci.yml:66-67, Clippy ci.yml:69-77, Test ci.yml:79-80,
# Build release ci.yml:82-84, cargo-deny ci.yml:86-92, daemon smoke
# ci.yml:94-103) plus the separate `security-audit` job's
# `cargo audit --deny warnings` (ci.yml:176-194), reordered
# cheapest-to-fail, plus one rustydns-specific convention gate (gate 2).
# Three differences from the YAML, named rather than skipped silently:
#   1. CI pins toolchain 1.88 (ci.yml:47-53); the repo-root
#      rust-toolchain.toml pins that same floor concretely as 1.88.0
#      (Cargo.toml:16 declares rust-version = "1.88"), and the preamble
#      below forces the gate onto that exact toolchain even when the
#      ambient cargo is not a rustup proxy (Homebrew's on macOS ignores
#      rust-toolchain.toml). Gate 1 keeps enforcing the 1.88 FLOOR.
#      CI's `stable` job (ci.yml:105-141) re-runs build+test on the latest
#      stable toolchain and again under --release: second-toolchain
#      coverage that stays CI-only.
#   2. CI's `docker` job (ci.yml:143-174) builds the image and smoke-runs
#      --version inside it. That needs Docker plus a full container
#      toolchain build; gate 9 exercises the same executable via
#      --validate-config on the host instead.
#   3. CI pins cargo-audit at 0.22.2 (ci.yml:191); locally whatever
#      version is installed runs, and a MISSING cargo-audit fails the
#      gate -- it is never skipped into green.
set -eu

cd "$(dirname "$0")/../.."

# ── Toolchain pin preamble (AQ-233) ────────────────────────────────────
# The gate must run the exact toolchain rust-toolchain.toml pins — never
# the ambient one. An ambient cargo that is not a rustup proxy (Homebrew's
# on macOS) ignores rust-toolchain.toml entirely, so this preamble
# resolves the pinned toolchain's bin dir via `rustup which` and puts it
# FIRST on PATH, then refuses (exit 1) unless the rustc and clippy that
# PATH now finds match the pin's minor. A missing or malformed
# rust-toolchain.toml, a missing rustup, or an uninstalled pin are hard
# refusals — the gate never silently starts on the ambient toolchain.
# Parsing is grep + parameter expansion only (no sed/awk/read: BSD/GNU
# divergence).
toolchain_fail() {
  printf 'GATE REFUSED (toolchain pin): %s\n' "$1" >&2
  exit 1
}
[ -f rust-toolchain.toml ] \
  || toolchain_fail 'rust-toolchain.toml missing — refusing to gate on the ambient toolchain'
channel_count=$(grep -c '^channel[[:space:]]*=' rust-toolchain.toml) || channel_count=0
[ "$channel_count" -eq 1 ] \
  || toolchain_fail "expected exactly one 'channel =' line in rust-toolchain.toml, found $channel_count"
channel_line=$(grep '^channel[[:space:]]*=' rust-toolchain.toml)
channel_value=${channel_line#*=}
channel_value=${channel_value#"${channel_value%%[![:space:]]*}"}
channel_value=${channel_value%"${channel_value##*[![:space:]]}"}
case $channel_value in
  \"*\") channel=${channel_value#\"} ;;
  *) toolchain_fail "channel value is not a double-quoted string: $channel_value" ;;
esac
channel=${channel%\"}
case $channel in
  [0-9]*.[0-9]*|[0-9]*.[0-9]*.[0-9]*) ;;
  *) toolchain_fail "unsupported channel '$channel' — this gate requires a concrete X.Y or X.Y.Z pin so the clippy-minor assertion is well-defined" ;;
esac
command -v rustup >/dev/null 2>&1 \
  || toolchain_fail 'rustup not on PATH — cannot resolve the pinned toolchain (an ambient-only install refuses here by design)'
pinned_cargo=$(rustup which --toolchain "$channel" cargo 2>/dev/null) \
  || toolchain_fail "toolchain '$channel' is not installed — run: rustup toolchain install $channel"
[ -x "$pinned_cargo" ] || toolchain_fail "resolved cargo is not executable: $pinned_cargo"
PATH=${pinned_cargo%/*}:$PATH
export PATH
# Assert the toolchain PATH now resolves really is the pin: rustc minor
# must equal the pinned minor, and clippy (0.1.N) must track that rustc.
rustc_banner=$(rustc --version 2>/dev/null) \
  || toolchain_fail 'rustc --version failed under the pinned PATH'
rustc_ver=${rustc_banner#* }
rustc_ver=${rustc_ver%% *}
case $rustc_ver in
  [0-9]*.[0-9]*) ;;
  *) toolchain_fail "unparsable 'rustc --version' output: $rustc_banner" ;;
esac
rustc_minor=${rustc_ver#*.}
rustc_minor=${rustc_minor%%.*}
clippy_banner=$(cargo clippy --version 2>/dev/null) \
  || toolchain_fail 'cargo clippy --version failed under the pinned PATH'
clippy_ver=${clippy_banner#* }
clippy_ver=${clippy_ver%% *}
case $clippy_ver in
  0.*.*) ;;
  *) toolchain_fail "unparsable 'cargo clippy --version' output: $clippy_banner" ;;
esac
clippy_minor=${clippy_ver#*.}
clippy_minor=${clippy_minor#*.}
clippy_minor=${clippy_minor%%[!0-9]*}
pin_minor=${channel#*.}
pin_minor=${pin_minor%%.*}
if [ "$rustc_minor" -ne "$pin_minor" ] || [ "$clippy_minor" -ne "$rustc_minor" ]; then
  toolchain_fail "PATH resolves rustc $rustc_ver / clippy $clippy_ver, not the pinned $channel"
fi
printf 'gate toolchain: pin %s — rustc %s, clippy %s (pinned bin dir first on PATH)\n' \
  "$channel" "$rustc_ver" "$clippy_ver"

# CI parity: the workflow sets RUSTFLAGS=-Dwarnings globally (ci.yml:26),
# so compiler warnings are errors in every cargo step below, exactly as
# in CI. Cost: the first local run rebuilds whatever the ambient
# (unset-RUSTFLAGS) cache held.
RUSTFLAGS='-Dwarnings'
export RUSTFLAGS

printf '=== 1/9 MSRV floor: rustc >= 1.88 (Cargo.toml rust-version) ===\n'
# rustc --version prints "rustc <semver> (<sha> <date>)". Split with
# parameter expansion only -- no sed/awk/date/read on this host.
set -- $(rustc --version)
rustc_ver=${2:?rustc printed no version}
rustc_major=${rustc_ver%%.*}
rustc_minor=${rustc_ver#*.}
rustc_minor=${rustc_minor%%.*}
if [ "$rustc_major" -lt 1 ] || { [ "$rustc_major" -eq 1 ] && [ "$rustc_minor" -lt 88 ]; }; then
  printf 'gate 1/9 FAILED: rustc %s is below the 1.88 MSRV floor (Cargo.toml rust-version)\n' "$rustc_ver"
  exit 1
fi

printf '=== 2/9 Secret redaction convention (crates/rustydns-core/src/config.rs) ===\n'
# charter/reviews/wave19-sweeps-2026-09-22/AQ-108-secret-display-sweep-v2.md
# records `pub struct Secret(String)` as the tree's model convention:
# manual redacting Debug, Zeroize + ZeroizeOnDrop, manual Serialize
# emitting a placeholder. The manual impls' EXISTENCE is compiler-enforced
# (a #[derive(Debug)] / #[derive(Serialize)] on Secret would be a
# conflicting-impl error, refused by gates 6/7) -- but their CONTENT is
# not, and the zeroize derives are enforced nowhere at all. This gate
# pins the content textually; a deliberate convention change must edit
# this gate in the same commit.
sec_file=crates/rustydns-core/src/config.rs
convention_fail() {
  printf 'gate 2/9 FAILED: %s\n' "$1"
  exit 1
}
sec_count=$(grep -c 'pub struct Secret(String);' "$sec_file") \
  || convention_fail 'Secret type not found in config.rs'
[ "$sec_count" -eq 1 ] || convention_fail "expected exactly one Secret type, found $sec_count"
sec_derive=$(grep -B2 'pub struct Secret(String);' "$sec_file")
printf '%s\n' "$sec_derive" | grep -q 'Zeroize,' \
  || convention_fail 'Secret derive lost Zeroize (expected "Clone, Deserialize, Zeroize, ZeroizeOnDrop")'
printf '%s\n' "$sec_derive" | grep -q 'ZeroizeOnDrop' \
  || convention_fail 'Secret derive lost ZeroizeOnDrop'
sec_dbg=$(grep -A2 'impl std::fmt::Debug for Secret' "$sec_file") \
  || convention_fail 'manual Debug impl for Secret not found'
printf '%s\n' "$sec_dbg" | grep -q '<redacted>' \
  || convention_fail 'Secret Debug impl no longer emits <redacted>'
sec_ser=$(grep -A3 'impl serde::Serialize for Secret' "$sec_file") \
  || convention_fail 'manual Serialize impl for Secret not found'
printf '%s\n' "$sec_ser" | grep -q '<redacted>' \
  || convention_fail 'Secret Serialize impl no longer emits <redacted>'

printf '=== 3/9 cargo fmt --all --check ===\n'
cargo fmt --all --check

printf '=== 4/9 cargo deny --all-features check ===\n'
# Full check (advisories+bans+licenses+sources), matching the CI action
# (ci.yml:86-92: command "check", arguments "--all-features" -- the
# action places --all-features BEFORE the subcommand, which is where
# cargo-deny's CLI wants it) and deny.toml's own "Run locally with:
# cargo deny check" header.
cargo deny --all-features check

printf '=== 5/9 cargo audit --deny warnings ===\n'
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit --deny warnings
else
  printf 'gate 5/9 FAILED: cargo-audit not installed (CI runs it, pinned 0.22.2, ci.yml:190-194).\n'
  printf '  install: cargo install cargo-audit --locked --version 0.22.2\n'
  exit 1
fi

printf '=== 6/9 cargo clippy --workspace --all-targets --tests -- -D clippy::all ===\n'
cargo clippy --workspace --all-targets --tests -- -D clippy::all

printf '=== 7/9 cargo test --workspace --all-targets --locked ===\n'
cargo test --workspace --all-targets --locked

printf '=== 8/9 cargo build --workspace --release --locked ===\n'
# Smoke-build the release profile so lto/strip surprises surface
# (ci.yml:82-84; [profile.release] lto = "thin").
cargo build --workspace --release --locked

printf '=== 9/9 daemon smoke: --validate-config on the example config ===\n'
# ci.yml:94-103: validate the example config schema offline. Mirrors the
# CI chmods (the example carries placeholder tokens; the config-perms
# invariant wants it non-world-readable) and honours CARGO_TARGET_DIR so
# the gate still finds the release binary the build above just made.
chmod 600 rustydns.example.toml
bin_dir=${CARGO_TARGET_DIR:-./target}
smoke_cfg=${TMPDIR:-/tmp}/rustydns-gates-validate.$$.toml
cp rustydns.example.toml "$smoke_cfg"
chmod 600 "$smoke_cfg"
trap 'rm -f "$smoke_cfg"' EXIT
"$bin_dir/release/rustydnsd" --config "$smoke_cfg" --validate-config

printf 'All 9 rustydns gates passed.\n'
