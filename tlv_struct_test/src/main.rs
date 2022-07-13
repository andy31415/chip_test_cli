use tlv_packed::TlvMergeDecodable;

#[macro_use]
extern crate tlv_derive;

#[derive(Debug, Default, PartialEq, Clone, Copy, TlvMergeDecodable)]
struct Test {
    nr: u32,
}

fn main() {
    println!("Hello, world!");
}
