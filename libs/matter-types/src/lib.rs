use core::fmt::Debug;

#[derive(Debug,  Copy, Clone, PartialEq)]
pub struct NodeId(pub u64);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct GroupId(pub u16);

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct VendorId(pub u16);

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct ProductId(pub u16);

impl Debug for ProductId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("ProductId(0x{:X})", self.0))
    }
}

impl Debug for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("VendorId(0x{:X})", self.0))
    }
}