#![no_main]

use libfuzzer_sys::fuzz_target;
use mirage_core::tls_parser::parse_dest_server_flight;

fuzz_target!(|data: &[u8]| {
    let _ = parse_dest_server_flight(data);
});
