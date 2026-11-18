#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mirage_core::mux::{decode_mux_frame, encode_mux_frame_into};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((frame, consumed))) = decode_mux_frame(data) {
        assert!(consumed <= data.len());
        let mut encoded = Vec::new();
        if encode_mux_frame_into(&frame, &mut encoded).is_ok() {
            let roundtrip = decode_mux_frame(&encoded);
            assert_eq!(roundtrip, Ok(Some((frame, encoded.len()))));
        }
    }
});
