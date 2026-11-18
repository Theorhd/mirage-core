#![no_main]

use libfuzzer_sys::fuzz_target;
use mirage_core::vision::{VisionPadder, VisionTlsFilter, VisionUnpadder};
use mirage_core::vless::VlessUuid;

fuzz_target!(|data: &[u8]| {
    let uuid = VlessUuid::from_bytes([0x22; 16]);
    let mut filter = VisionTlsFilter::new();
    filter.inspect(data);

    let mut padder = VisionPadder::new(uuid.clone());
    let wrapped = padder.wrap_outbound(data, &filter, 0x1234_5678);

    let mut unpadder = VisionUnpadder::new(uuid);
    let _ = unpadder.feed(&wrapped);
    let _ = unpadder.feed(data);
});
