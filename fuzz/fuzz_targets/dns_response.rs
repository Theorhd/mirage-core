#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use miraged::dns::parse_dns_response;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let tx_id = u16::from_be_bytes([data[0], data[1]]);
        let _ = parse_dns_response(data, tx_id, 1);
        let _ = parse_dns_response(data, tx_id, 28);
    } else {
        let _ = parse_dns_response(data, 0, 1);
    }
});
