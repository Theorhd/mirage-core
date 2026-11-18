#![no_main]

use libfuzzer_sys::fuzz_target;
use mirage_core::vless::{decode_udp_packet, parse_vless_request, VlessUuid};

fuzz_target!(|data: &[u8]| {
    let allowed = [VlessUuid::from_bytes([0x11; 16])];
    let mut buf = data.to_vec();
    let _ = parse_vless_request(&mut buf, &allowed);
    let _ = decode_udp_packet(data);
});
