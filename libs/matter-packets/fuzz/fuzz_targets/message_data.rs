#![no_main]
use libfuzzer_sys::fuzz_target;

use matter_packets::*;

fuzz_target!(|data: &[u8]| {
    let mut data = Vec::from(data);
    let mut data = data.as_mut_slice();
    MessageHeader::parse(&mut data).ok();
});
