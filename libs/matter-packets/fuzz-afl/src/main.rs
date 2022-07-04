#[macro_use]
extern crate afl;

use matter_packets::packet::Header;
use matter_packets::writer::SliceLittleEndianWriter;

fn main() {
    fuzz!(|data: &[u8]| {
        let mut data = Vec::from(data);
        let mut data = data.as_mut_slice();
        if let Ok(hdr) = Header::parse(&mut data) {
            // ensure write and re-read are the same
            let mut buff = [0u8; 64];
            let cnt = {
                let mut writer = SliceLittleEndianWriter::new(buff.as_mut_slice());
                assert!(hdr.write(&mut writer).is_ok());
                writer.written()
            };

            let mut data = &buff[0..cnt];
            let hdr2 = Header::parse(&mut data).unwrap();
            assert_eq!(hdr, hdr2);
        }
    });
}
