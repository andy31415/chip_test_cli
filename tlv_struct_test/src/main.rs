#[macro_use]
extern crate tlv_derive;

#[derive(Debug, Default, PartialEq, Clone, Copy, TlvMergeDecodable)]
struct Test {
    #[tlv_tag="context:1"]
    nr: u32,

    #[tlv_tag="context:2"]
    more_nr: u16,

    #[tlv_tag="full: 0xabcd"]
    opt_nr: Option<u32>,
}

fn main() {
    println!("Hello, world!");
}
