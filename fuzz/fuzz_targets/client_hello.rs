#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mirage_core::tls_parser::{inspect_client_hello, DEFAULT_MAX_CLIENT_HELLO_BYTES};

fuzz_target!(|data: &[u8]| {
    let _ = inspect_client_hello(data, DEFAULT_MAX_CLIENT_HELLO_BYTES);
});
