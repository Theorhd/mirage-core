# mirage-core

A memory-safe, modular, high-performance Rust implementation of the **Xray-Reality** TLS camouflage protocol coupled with **VLESS** and **XTLS-Vision**, built on a strict **Sans-I/O** protocol core and an asynchronous **Tokio** server runtime.

---

## Project Objective

`mirage-core` is designed to run a stealth proxy node on a VPS inside a minimal, hardened container (`FROM scratch`, read-only filesystem, non-root, zero Linux capabilities) while achieving three core goals:

1. **Zero-Fingerprint TLS Camouflage**: Eliminates detectable server-side TLS fingerprints by masquerading behind a legitimate third-party TLS 1.3 destination (`dest` / `SNI`) instead of terminating TLS with self-signed or anomalous certificates.
2. **Active Anti-Probing**: Every unauthenticated connection, malformed packet, or active DPI probe is transparently replayed at the raw TCP layer—byte-for-byte from the initial buffer—to the legitimate `dest` server, exposing its genuine X.509 certificate chain, ALPN/HTTP/2 behavior, and real network timing.
3. **Strict Wire-Compatibility**: Aims for full binary interoperability with existing Xray-Reality / VLESS clients, including **Xray-core**, **Shadowrocket**, **Clash Verge Rev**, and **v2rayN**.

---

## Protocol Operation & Connection Flow

Unlike traditional TLS servers that hand sockets directly to `rustls` or `tokio-rustls`, `mirage-core` performs **non-destructive raw TCP interception**. Initial bytes are read into a `BytesMut` buffer and inspected before deciding whether to authenticate the session or fall back to the real destination:

```text
  Client (Proxy or DPI Probe)
     │
     │  TCP Connect + TLS ClientHello
     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ miraged (Tokio TcpListener)                                             │
│   └─ Read initial bytes into BytesMut (non-destructive buffering)       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ mirage-core::tls_parser & reality (Sans-I/O Inspection)                 │
│   1. Parse TLS Record & ClientHello (SNI, key_share X25519, Session ID) │
│   2. Derive shared secret: X25519(server_privkey, client_key_share)     │
│   3. Expand key via HKDF-SHA256 & decrypt 32-byte Session ID via AEAD   │
│   4. Validate ShortID & anti-replay timestamp window                    │
└──────────────────────────┬───────────────────────────┬──────────────────┘
                           │                           │
            Auth Valid     │                           │  Auth Failed / Non-TLS / Probe
                           ▼                           ▼
         ┌───────────────────────────────────┐ ┌───────────────────────────────────┐
         │ Authenticated Reality Branch      │ │ Transparent TCP Fallback Branch   │
         │                                   │ │                                   │
         │ 1. Complete Reality TLS 1.3 flow  │ │ 1. Connect to legitimate `dest`   │
         │ 2. Parse VLESS header (UUID, Cmd) │ │ 2. Replay intact BytesMut buffer  │
         │ 3. Apply XTLS-Vision padding /    │ │ 3. Relay raw TCP bidirectionally  │
         │    Application Data detection     │ │    (tokio::io::copy_bidirectional)│
         │ 4. Route TCP/UDP to target host   │ │    -> Real cert & HTTP/2 exposed  │
         └───────────────────────────────────┘ └───────────────────────────────────┘
```

---

## Cargo Workspace Architecture

The repository is structured as a **Cargo Workspace** that strictly decouples pure protocol logic (**Sans-I/O**) from network I/O and process orchestration:

```text
mirage-core/
├── Cargo.toml                  # Cargo Workspace manifest
├── Dockerfile                  # Multi-stage static musl build -> FROM scratch
├── docker-compose.yml          # Hardened VPS deployment (read-only, cap_drop ALL, UID 65534)
├── crates/
│   ├── mirage-core/            # Pure Sans-I/O protocol library (no sockets, no async I/O)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs          # Public protocol exports & error types
│   │       ├── tls_parser.rs   # Zero-copy / non-destructive ClientHello parser (SNI, key_share, SessionID)
│   │       ├── crypto.rs       # X25519 ECDH, HKDF-SHA256, AEAD (AES-GCM / ChaCha20-Poly1305)
│   │       ├── reality.rs      # Reality handshake state machine (Auth vs Fallback)
│   │       ├── vless.rs        # Binary VLESS codec (Version, UUID, Addons, TCP/UDP commands)
│   │       └── vision.rs       # XTLS-Vision (TLS-in-TLS padding & Application Data detection)
│   └── miraged/                # Tokio asynchronous server binary
│       ├── Cargo.toml
│       └── src/
│           └── main.rs         # CLI, TOML configuration, socket accept loop, tracing
└── README.md
```

### Crate Separation

| Crate | Responsibility | Characteristics |
| --- | --- | --- |
| **`mirage-core`** | Protocol parsing, cryptography, and state machines | Pure **Sans-I/O**; operates solely on byte slices/buffers (`bytes`). Deterministically unit-testable without network sockets or async timers. |
| **`miraged`** | Server daemon, CLI, configuration, and async networking | Built on **Tokio**, `serde` + `toml`, and `tracing`. Manages TCP listeners, `BytesMut` peeking/buffering, fallback relays, and upstream connections. |

### Technology Stack & Toolchain

* **Rust**: Edition `2021` (or `2024`), MSRV `1.84+`
* **Async & Buffering**: `tokio`, `bytes`
* **TLS Parsing**: `tls-parser` or custom zero-allocation binary parser
* **Cryptography**: `x25519-dalek`, `aws-lc-rs` / `ring`
* **Configuration & Telemetry**: `serde`, `toml`, `tracing`
* **Release Targets**: Static musl binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`

---

## Security Principles

1. **Sans-I/O Isolation**: Separating state machines and cryptographic verification from socket I/O minimizes attack surface, avoids hidden state coupling, and enables thorough fuzzing and boundary testing on raw byte inputs.
2. **Non-Destructive TCP Interception**: The initial `ClientHello` is never delegated to `rustls` or `tokio-rustls`. Keeping the original TCP payload intact inside `BytesMut` guarantees that fallback relays reproduce the exact client bytes when forwarding to `dest`.
3. **Replay & Probe Resistance**: Reality Session ID verification validates both the AEAD authentication tag (derived via X25519 + HKDF-SHA256) and a strict timestamp/ShortID window, mitigating replay attacks and passive/active probing.
4. **Hardened Container Runtime (`FROM scratch`)**:
   * Multi-stage static compilation against `musl` with stripped debug symbols.
   * Runtime image contains only the static binary—no libc dynamic loader, no shell (`/bin/sh`), and no package manager.
   * Executed as an unprivileged user (`UID 65534`), with a read-only root filesystem (`read_only: true`) and all Linux capabilities dropped (`cap_drop: [ALL]`).

---

## Roadmap

* [ ] **Milestone 1 — SNI Proxy & TCP Fallback**
  * Async TCP listener in `miraged` with `BytesMut` initial-packet buffering.
  * Non-destructive TLS `ClientHello` parsing (`SNI`, `Session ID`, `key_share`) in `mirage-core::tls_parser`.
  * Transparent bidirectional TCP fallback (`tokio::io::copy_bidirectional`) to `dest`.
* [ ] **Milestone 2 — Reality Cryptographic Handshake**
  * X25519 ECDH key agreement, HKDF-SHA256 key derivation, and AEAD verification (`crypto.rs`).
  * Session ID decryption, `ShortID` matching, and anti-replay timestamp checks (`reality.rs`).
  * Completion of the authenticated Reality TLS 1.3 handshake flow.
* [ ] **Milestone 3 — VLESS Protocol & XTLS-Vision**
  * Binary VLESS request/response framing (version, UUID authentication, addons, TCP/UDP commands) in `vless.rs`.
  * XTLS-Vision TLS-in-TLS padding and inner Application Data detection (`vision.rs`).
  * Full upstream TCP/UDP proxying.
* [ ] **Milestone 4 — Packaging & Hardening**
  * TOML configuration loading and CLI keypair / ShortID / UUID generation utilities.
  * Multi-stage `Dockerfile` targeting `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` onto `FROM scratch`.
  * Hardened `docker-compose.yml` (`read_only`, `cap_drop: ALL`, `no-new-privileges`, `UID 65534`).

---

## Development Workflow

* **`main`**: Stable production branch (compilable, tested, and documented).
* **`dev`**: Primary integration branch for active development. Feature and fix branches (`feat/...`, `fix/...`) branch from and merge into `dev` before promotion to `main`.
* Commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`docs:`, `feat:`, `chore:`, `fix:`, `refactor:`).

---

## Legal Disclaimer

This project is provided strictly for **educational purposes, cryptographic engineering study, and authorized network research**. Users are solely responsible for complying with all applicable local, national, and international laws, regulations, and network acceptable-use policies. The authors and contributors assume no liability for any misuse of this software.
