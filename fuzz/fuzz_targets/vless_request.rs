#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mirage_core::vless::{decode_udp_packet, parse_vless_request, VlessUuid};

fuzz_target!(|data: &[u8]| {
    let allowed = [VlessUuid::from_bytes([0x11; 16])];
    let mut raw = data.to_vec();
    let _ = parse_vless_request(&mut raw, &allowed);

    // Prepend version=0x00 + matching UUID so the fuzzer immediately exercises
    // protobuf addons, command/address parsing, and IPv4/domain/IPv6 paths.
    let mut auth_buf = Vec::with_capacity(17usize.saturating_add(data.len()));
    auth_buf.push(0x00);
    auth_buf.extend_from_slice(&[0x11; 16]);
    auth_buf.extend_from_slice(data);
    let _ = parse_vless_request(&mut auth_buf, &allowed);

    let _ = decode_udp_packet(data);
});
