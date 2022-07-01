use anyhow::{anyhow, Result};
use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};

use matter_types::VendorId;
use matter_types::ProductId;

use core::fmt::Debug;

bitflags! {
    pub struct ComissionableFlags: u8 {
        const ADDITIONAL_DATA = 0x01;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Discriminator(pub u16); // 12 bit max

/// Represends data that is beaconed over BLE by a matter
/// device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Commissionable {
    pub discriminator: Discriminator,
    pub vendor_id: Option<VendorId>,
    pub product_id: Option<ProductId>,
    pub flags: ComissionableFlags,
}

impl Commissionable {
    /// Parses commissionable data.
    ///
    /// Example:
    ///
    /// ```
    /// use matter_types::*;
    /// use matter_btp::advertising_data::{Commissionable, Discriminator, ComissionableFlags};
    ///
    /// // buffer too short
    /// assert!(Commissionable::parse(&[]).is_err());
    ///
    /// assert_eq!(
    ///   Commissionable::parse(&[
    ///      0x00,       // 0x00 is commissionable upcode
    ///      0xd2, 0x04, // 1234 - 12-bit discriminator
    ///      0x00, 0x00, // vendor id (0 is undefined)
    ///      0x00, 0x00, // product id (0 is undefined)
    ///      0x00        // flags
    ///   ]).unwrap(),
    ///   Commissionable {
    ///      discriminator: Discriminator(1234),
    ///      vendor_id: None,
    ///      product_id: None,
    ///      flags: ComissionableFlags::empty(),
    ///   }
    /// );
    ///
    /// assert_eq!(
    ///   Commissionable::parse(&[
    ///      0x00,       // 0x00 is commissionable upcode
    ///      0x8a, 0x0c, // 3210 - 12-bit discriminator
    ///      0x11, 0x22, // vendor id (0 is undefined)
    ///      0x33, 0x44, // product id (0 is undefined)
    ///      0x01        // flags
    ///   ]).unwrap(),
    ///   Commissionable {
    ///      discriminator: Discriminator(3210),
    ///      vendor_id: Some(VendorId(0x2211)),
    ///      product_id: Some(ProductId(0x4433)),
    ///      flags: ComissionableFlags::ADDITIONAL_DATA,
    ///   }
    /// );
    /// ```
    pub fn parse(data: &[u8]) -> Result<Commissionable> {
        if data.len() < 8 {
            return Err(anyhow!("Advertising data too short"));
        }
        // Advertising format:
        //   - 1 byte:    matter op-code. 0x00 is 'Commissionable', the rest are undefined
        //   - 2 byte LE: 4 bits version (0 is supported), 12 bits discriminator
        //   - 2 byte LE: vendor id. 0 means undefined/missing
        //   - 2 byte LE: product id. 0 means undefined/missing
        //   - 1 byte:    flags. bit0 is 'additional data' flag, rest are reserved and MUST be 0
        let opcode = data[0];

        if opcode != 0x00 {
            return Err(anyhow!(
                "Unsupported opcode. Only Commissionable (0x00) is supported."
            ));
        }

        let version_and_discriminator = LittleEndian::read_u16(&data[1..3]);
        let vendor_id = LittleEndian::read_u16(&data[3..5]);
        let product_id = LittleEndian::read_u16(&data[5..7]);
        let flags = data[7];

        let version = (version_and_discriminator >> 12) & 0x0F;

        if version != 0 {
            return Err(anyhow!(
                "Unsupported commissionable payload version: {}",
                version
            ));
        }

        let discriminator = Discriminator(version_and_discriminator & 0x0FFF);
        let vendor_id = if vendor_id == 0 {
            None
        } else {
            Some(VendorId(vendor_id))
        };
        let product_id = if product_id == 0 {
            None
        } else {
            Some(ProductId(product_id))
        };

        let flags = ComissionableFlags::from_bits(flags)
            .ok_or_else(|| anyhow!("Unable to parse flags {:x}", flags))?;

        Ok(Commissionable {
            discriminator,
            vendor_id,
            product_id,
            flags,
        })
    }
}
