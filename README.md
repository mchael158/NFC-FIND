# NFC-FIND

NFC relay prototype for authorized contactless-payment security assessment.
Written in Rust with an optional hand-written x86-64 assembly helper.

## How it works

A contactless (NFC) relay attack bridges two endpoints over a network:

- **Reader side** (`reader`): sits next to the victim's card, reads APDUs from it
  (via PC/SC when a real reader is attached, or a mock card in simulation mode),
  and forwards them over TCP.
- **Terminal side** (`terminal`): sits next to the payment terminal, receives
  APDUs over TCP, sends them to the terminal, and returns the responses.

Frames are length-prefixed JSON over TCP, with a 30s I/O timeout. Each APDU
exchange is logged with its round-trip latency, which is useful for relay
detection research (relay attacks add measurable delay).

A handshake validates an `engagement` token on both sides. The core logic is
synchronous and `#![no_std]`-capable (requires `alloc`), so it can be reused on
embedded targets such as ESP32; the desktop binary adds std I/O, CLI, and
threading on top.

## Modes

- **Mock mode (default):** the reader side simulates a card (random GET
  CHALLENGE response, `6D00` for other instructions). No hardware required.
- **Real mode:** compile with `--features pcsc-backend` and pass `--use-pcsc`
  to talk to a real NFC reader via PC/SC.

## Build

```sh
cargo build            # mock mode
cargo build --release  # optimized
cargo test             # run the 4 core unit tests
cargo test --lib       # library tests only
```

The crate is split into a portable core library (`src/lib.rs`, `#![no_std]`
with `alloc`) and a desktop binary (`src/main.rs`). The assembly helpers in
`asm/` are standalone reference implementations; the core uses a pure-Rust CRC
so it builds on any target, including ESP32.

## Usage

Authorization is required via environment variables:

```sh
export NFC_RELAY_AUTHORIZED=1
export NFC_RELAY_ENGAGEMENT="engagement-name"
export NFC_RELAY_ENV="authorized-pentest"   # optional, default: lab
```

On Windows (PowerShell):

```powershell
$env:NFC_RELAY_AUTHORIZED = "1"
$env:NFC_RELAY_ENGAGEMENT = "engagement-name"
```

### Self-contained demo (no hardware)

Runs reader + terminal in one process:

```sh
NFC_RELAY_AUTHORIZED=1 NFC_RELAY_ENGAGEMENT=demo cargo run -- demo
```

### Reader side

```sh
# Mock card, with APDU logging
cargo run -- reader --listen 0.0.0.0:9876 --log-file relay.log

# Real card via PC/SC
cargo run --features pcsc-backend -- reader --listen 0.0.0.0:9876 --use-pcsc --log-file relay.log
```

### Terminal side

```sh
# Built-in probe APDUs
cargo run -- terminal --backend 127.0.0.1:9876

# Replay APDUs from a file (one hex APDU per line)
cargo run -- terminal --backend 127.0.0.1:9876 --apdu-file apdus.txt
```

### CRC helper

```sh
cargo run -- crc --hex 00a404000e325041592e5359532e4444463031
# -> CRC-16/ISO14443-A = 0x5D19
```

## APDU file format

One APDU per line, hex (spaces allowed), lines starting with `#` are comments:

```
# GET CHALLENGE
00 84 00 00 08
# SELECT PPSE
00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31
```

## Project layout

- `src/lib.rs` - crate root (`#![no_std]` + `alloc`).
- `src/core.rs` - portable core: types, traits (`NfcReader`, `Transport`),
  frames, sync relay logic, CRC-16. No `unwrap` in production paths.
- `src/main.rs` - desktop binary: std I/O, CLI, threading, mock/PC-SC readers.
- `asm/` - standalone CRC-16 helpers (MASM + NASM) for reference.
- `Cargo.toml` / `Cargo.lock` - manifest and locked dependencies.

## Limitations

A full relay that fools a real payment terminal requires card emulation (HCE)
in hardware, which is outside the scope of this software prototype. This tool
provides the network relay, latency measurement, and APDU logging, which are
the parts usable for authorized research.

## Warning

Restricted to authorized environments (contracted pentest / lab). Use outside
an authorized scope is illegal and the operator's responsibility.
