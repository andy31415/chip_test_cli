#![no_main]
use libfuzzer_sys::fuzz_target;

use matter_packets::*;

fuzz_target!(|data: &[u8]| {
    let data = ConstU8LittleEndianReader::new(data);
    MessageData::parse(data);
});
