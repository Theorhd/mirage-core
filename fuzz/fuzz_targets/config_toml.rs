#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use miraged::config::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = Config::from_toml_str(s);
    }
});
