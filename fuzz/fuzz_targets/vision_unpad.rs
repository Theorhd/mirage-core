#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mirage_core::vision::{VisionPadder, VisionTlsFilter, VisionUnpadder};
use mirage_core::vless::VlessUuid;

fuzz_target!(|data: &[u8]| {
    let uuid = VlessUuid::from_bytes([0x22; 16]);
    let mut up_filter = VisionTlsFilter::new();
    up_filter.inspect_uplink(data);

    let mut down_filter = VisionTlsFilter::new();
    down_filter.inspect_downlink(data);

    let mut padder = VisionPadder::new(uuid.clone());
    let wrapped = padder.wrap_outbound(data, &down_filter, 0x1234_5678);

    let mut unpadder_rt = VisionUnpadder::new(uuid.clone());
    if let Ok(out) = unpadder_rt.feed(&wrapped) {
        assert_eq!(out.payload.as_slice(), data);
    }

    // Exercise unpadded/malformed framing paths with a valid UUID prefix and split chunks.
    let mut prefixed = Vec::with_capacity(16usize.saturating_add(data.len()));
    prefixed.extend_from_slice(&[0x22; 16]);
    prefixed.extend_from_slice(data);
    let mid = prefixed.len() / 2;
    let mut unpadder_raw = VisionUnpadder::new(uuid);
    let _ = unpadder_raw.feed(&prefixed[..mid]);
    let _ = unpadder_raw.feed(&prefixed[mid..]);
});
