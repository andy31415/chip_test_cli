use std::{error::Error, fmt::Display};

use anyhow::{anyhow, Result};
use derive_builder::Builder;
use matter_types::{ExchangeId, VendorId};

use crate::{reader::LittleEndianReader, writer::LittleEndianWriter};

/// an error when parsing a protocol
#[derive(PartialEq, Debug)]
pub enum ProtocolOpCodeError {
    UnknownProtocolId,
    InvalidVendorId,
    UnknownOpCode,
}

pub trait ProtocolInfo {
    fn protocol_id(&self) -> u16;
    fn protocol_opcode(&self) -> u8;
}

impl Display for ProtocolOpCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolOpCodeError::UnknownProtocolId => {
                f.write_str("Unknown protocol id for standard protocols")
            }
            ProtocolOpCodeError::InvalidVendorId => {
                f.write_str("Not a valid vendor id for a protocol")
            }
            ProtocolOpCodeError::UnknownOpCode => f.write_str("Unknown protocol opcode"),
        }
    }
}

impl Error for ProtocolOpCodeError {}

/// Opcodes specific to secure channel
#[repr(u8)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum SecureChannelOpcode {
    MessageCounterSyncRequest = 0x00,
    MessageCounterSyncResponse = 0x01,
    MrpStandaloneAck = 0x10,
    PbkdfParamRequest = 0x20,
    PbkdfParamResponse = 0x21,
    PasePake1 = 0x22,
    PasePake2 = 0x23,
    PasePake3 = 0x24,
    CaseSigma1 = 0x30,
    CaseSigma2 = 0x31,
    CaseSigma3 = 0x32,
    CaseSigma2Resume = 0x33,
    StatusReport = 0x40,
}

impl TryFrom<u8> for SecureChannelOpcode {
    type Error = ProtocolOpCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SecureChannelOpcode::MessageCounterSyncRequest),
            0x01 => Ok(SecureChannelOpcode::MessageCounterSyncResponse),
            0x10 => Ok(SecureChannelOpcode::MrpStandaloneAck),
            0x20 => Ok(SecureChannelOpcode::PbkdfParamRequest),
            0x21 => Ok(SecureChannelOpcode::PbkdfParamResponse),
            0x22 => Ok(SecureChannelOpcode::PasePake1),
            0x23 => Ok(SecureChannelOpcode::PasePake2),
            0x24 => Ok(SecureChannelOpcode::PasePake3),
            0x30 => Ok(SecureChannelOpcode::CaseSigma1),
            0x31 => Ok(SecureChannelOpcode::CaseSigma2),
            0x32 => Ok(SecureChannelOpcode::CaseSigma3),
            0x33 => Ok(SecureChannelOpcode::CaseSigma2Resume),
            0x40 => Ok(SecureChannelOpcode::StatusReport),
            _ => Err(ProtocolOpCodeError::UnknownOpCode),
        }
    }
}

/// Opcodes specific to interaction model
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum InteractionModelOpcode {
    StatusResponse = 0x01,
    ReadRequest = 0x02,
    SubscribeRequest = 0x03,
    SubscribeResponse = 0x04,
    ReportData = 0x05,
    WriteRequest = 0x06,
    WriteResponse = 0x07,
    InvokeRequest = 0x08,
    InvokeResponse = 0x09,
    TimedRequest = 0x0A,
}

impl TryFrom<u8> for InteractionModelOpcode {
    type Error = ProtocolOpCodeError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x01 => Ok(InteractionModelOpcode::StatusResponse),
            0x02 => Ok(InteractionModelOpcode::ReadRequest),
            0x03 => Ok(InteractionModelOpcode::SubscribeRequest),
            0x04 => Ok(InteractionModelOpcode::SubscribeResponse),
            0x05 => Ok(InteractionModelOpcode::ReportData),
            0x06 => Ok(InteractionModelOpcode::WriteRequest),
            0x07 => Ok(InteractionModelOpcode::WriteResponse),
            0x08 => Ok(InteractionModelOpcode::InvokeRequest),
            0x09 => Ok(InteractionModelOpcode::InvokeResponse),
            0x0A => Ok(InteractionModelOpcode::TimedRequest),
            _ => Err(ProtocolOpCodeError::UnknownOpCode),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BdxOpcode {
    SendInit = 0x01,
    SendAccept = 0x02,
    ReceiveInit = 0x04,
    ReceiveAccept = 0x05,
    BlockQuery = 0x10,
    Block = 0x11,
    BlockEOF = 0x12,
    BlockAck = 0x13,
    BlockAckEOF = 0x14,
    BlockQueryWithSkip = 0x15,
}

impl TryFrom<u8> for BdxOpcode {
    type Error = ProtocolOpCodeError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x01 => Ok(BdxOpcode::SendInit),
            0x02 => Ok(BdxOpcode::SendAccept),
            0x04 => Ok(BdxOpcode::ReceiveInit),
            0x05 => Ok(BdxOpcode::ReceiveAccept),
            0x10 => Ok(BdxOpcode::BlockQuery),
            0x11 => Ok(BdxOpcode::Block),
            0x12 => Ok(BdxOpcode::BlockEOF),
            0x13 => Ok(BdxOpcode::BlockAck),
            0x14 => Ok(BdxOpcode::BlockAckEOF),
            0x15 => Ok(BdxOpcode::BlockQueryWithSkip),
            _ => Err(ProtocolOpCodeError::UnknownOpCode),
        }
    }
}

/// Opcodes specific to user directed commissioning
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum UserDirectedCommissioningOpcode {
    IdentificationDeclaration = 0x00,
}

impl TryFrom<u8> for UserDirectedCommissioningOpcode {
    type Error = ProtocolOpCodeError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x00 => Ok(UserDirectedCommissioningOpcode::IdentificationDeclaration),
            _ => Err(ProtocolOpCodeError::UnknownOpCode),
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ProtocolOpCode {
    SecureChannel(SecureChannelOpcode),
    InteractionModel(InteractionModelOpcode),
    Bdx(BdxOpcode),
    UserDirectedCommissioning(UserDirectedCommissioningOpcode),

    // Generic vendor specific
    Vendor {
        vendor_id: u16,
        protocol: u16,
        opcode: u8,
    },
}

impl ProtocolOpCode {
    /// parse a tuple of protocol id and opcode id and return the underlying known opcode value.
    pub fn from_raw(
        raw_vendor_id: Option<VendorId>,
        raw_protocol_id: u16,
        raw_opcode: u8,
    ) -> Result<ProtocolOpCode, ProtocolOpCodeError> {
        if let Some(VendorId(vendor_id)) = raw_vendor_id {
            if vendor_id == 0 {
                return Err(ProtocolOpCodeError::InvalidVendorId);
            }

            Ok(ProtocolOpCode::Vendor {
                vendor_id,
                protocol: raw_protocol_id,
                opcode: raw_opcode,
            })
        } else {
            match raw_protocol_id {
                0 => Ok(ProtocolOpCode::SecureChannel(
                    SecureChannelOpcode::try_from(raw_opcode)?,
                )),
                1 => Ok(ProtocolOpCode::InteractionModel(
                    InteractionModelOpcode::try_from(raw_opcode)?,
                )),
                2 => Ok(ProtocolOpCode::Bdx(BdxOpcode::try_from(raw_opcode)?)),
                3 => Ok(ProtocolOpCode::UserDirectedCommissioning(
                    UserDirectedCommissioningOpcode::try_from(raw_opcode)?,
                )),
                _ => Err(ProtocolOpCodeError::UnknownProtocolId),
            }
        }
    }
}

impl ProtocolInfo for ProtocolOpCode {
    /// Return the underlying protocol id for the given opcode
    fn protocol_id(&self) -> u16 {
        match self {
            ProtocolOpCode::SecureChannel(_) => 0,
            ProtocolOpCode::InteractionModel(_) => 1,
            ProtocolOpCode::Bdx(_) => 2,
            ProtocolOpCode::UserDirectedCommissioning(_) => 3,
            ProtocolOpCode::Vendor { protocol, .. } => *protocol,
        }
    }

    /// Fetch the protocol opcode for the given protocol
    ///
    /// # Examples
    ///
    /// ```
    /// use matter_packets::payload::{ProtocolOpCode, SecureChannelOpcode, BdxOpcode, ProtocolInfo};
    ///
    /// assert_eq!(ProtocolOpCode::Bdx(BdxOpcode::BlockEOF).protocol_opcode(), 0x12);
    /// assert_eq!(ProtocolOpCode::SecureChannel(SecureChannelOpcode::PasePake2).protocol_opcode(), 0x23);
    /// ```
    fn protocol_opcode(&self) -> u8 {
        match self {
            ProtocolOpCode::SecureChannel(v) => *v as u8,
            ProtocolOpCode::InteractionModel(v) => *v as u8,
            ProtocolOpCode::Bdx(v) => *v as u8,
            ProtocolOpCode::UserDirectedCommissioning(v) => *v as u8,
            ProtocolOpCode::Vendor { opcode, .. } => *opcode,
        }
    }
}

bitflags::bitflags! {
    /// Represents security flags within the message header
    pub struct ExchangeFlags: u8 {
       const INITIATOR = 0b_0000_0001;
       const ACKNOWLEDGEMENT = 0b_0000_0010;
       const RELIABILITY = 0b_0000_0100;
       const SECURED_EXTENSIONS = 0b_0000_1000;
       const VENDOR = 0b_0001_0000;
    }
}

impl Default for ExchangeFlags {
    fn default() -> Self {
        ExchangeFlags::empty()
    }
}

/// A protocol header.
///
///
/// # Binary layout
///
/// | Size           | Description                               |
/// |----------------|-------------------------------------------|
/// | `u8`           | Exchange flags                            |
/// | `u8`           | Protocol opcode                           |
/// | `u16`          | Exchange Id                               |
/// | `u16`          | Protocol Id                               |
/// | `0/u16`        | (Optional) Vendor Id                      |
/// | `0/u32`        | (Optional) Ack counter                    |
/// | `u16 + (len)`  | (Optional) u16-length prefixed extensions |
/// | *              | Payload                                   |
#[derive(Builder, Debug, Clone, Copy)]
pub struct Header {
    #[builder(default)]
    pub flags: ExchangeFlags,

    /// contains both protocol id and opcode
    pub protocol_opcode: ProtocolOpCode,

    pub exchange: ExchangeId,

    #[builder(default)]
    pub ack_counter: Option<u32>,
}

impl Header {
    /// Parses a given buffer and interprets it as a MATTER message.
    ///
    /// It does NOT skip over secured extensions (but flag is parsed and can
    /// be used as needed).
    ///
    /// Examples:
    ///
    /// ```
    /// use matter_types::*;
    /// use matter_packets::payload::*;
    ///
    /// // invalid messages are rejected
    /// let mut data: &[u8] = &[]; // too short
    /// assert!(Header::parse(&mut data).is_err()); // too short
    ///
    /// let mut data: &[u8] = &[
    ///    0x00,         // exchange flags
    ///    0x22,         // Pake1 (for secure channel)
    ///    0x12, 0x23,   // Exchange Id
    ///    0x00, 0x00,   // secure channel protocol,
    ///    0xab, 0xff, 0x12   // payload
    /// ];
    /// let header = Header::parse(&mut data).unwrap();
    ///
    /// assert_eq!(header.flags, ExchangeFlags::empty());
    /// assert_eq!(header.exchange, ExchangeId(0x2312));
    /// assert_eq!(header.protocol_opcode, ProtocolOpCode::SecureChannel(SecureChannelOpcode::PasePake1));
    /// assert_eq!(data, &[0xab, 0xff, 0x12]);
    ///
    /// ```
    ///
    ///
    pub fn parse(buffer: &mut impl LittleEndianReader) -> Result<Header> {
        let flags = ExchangeFlags::from_bits(buffer.read_le_u8()?)
            .ok_or_else(|| anyhow!("Invalid exchange flags"))?;
        let opcode = buffer.read_le_u8()?;
        let exchange = ExchangeId(buffer.read_le_u16()?);
        let protocol = buffer.read_le_u16()?;

        let vendor_id = if flags.contains(ExchangeFlags::VENDOR) {
            Some(VendorId(buffer.read_le_u16()?))
        } else {
            None
        };

        let ack_counter = if flags.contains(ExchangeFlags::ACKNOWLEDGEMENT) {
            Some(buffer.read_le_u32()?)
        } else {
            None
        };

        // NOTE: this does NOT skip over extensions here
        Ok(Header {
            flags,
            protocol_opcode: ProtocolOpCode::from_raw(vendor_id, protocol, opcode)?,
            exchange,
            ack_counter,
        })
    }

    /// Writes a header to the given endian writer
    ///
    /// # Example - simple data
    ///
    /// ```
    /// use matter_packets::{payload::{self, *}, writer::*};
    /// use matter_types::*;
    ///
    /// let header = payload::HeaderBuilder::default()
    ///     .protocol_opcode(ProtocolOpCode::SecureChannel(SecureChannelOpcode::PasePake2))
    ///     .exchange(ExchangeId(123))
    ///     .build()
    ///     .unwrap();
    ///
    /// let mut buffer = [0u8; 10];
    /// let cnt = {
    ///    let mut writer = SliceLittleEndianWriter::new(buffer.as_mut_slice());
    ///    assert!(header.write(&mut writer).is_ok());
    ///    writer.written()
    /// };
    ///
    /// assert_eq!(cnt, 6);
    /// assert_eq!(buffer.as_slice(), &[
    ///   0x00,       // no flags
    ///   0x23,       // PAKE2
    ///   123, 0,     // Exchange id
    ///   0x00, 0x00, // Secure channel protocol
    ///   // rest of data unchanged
    ///   0, 0, 0, 0
    /// ]);
    /// ```
    ///
    /// # Example - more fields set
    ///
    /// ```
    /// use matter_packets::{payload::{self, *}, writer::*};
    /// use matter_types::*;
    ///
    ///
    /// // NOTE: given the the protocol is based on a vendor, the underlying protocol ID is NOT ok here
    /// //       FIXME: implement a proper decoding
    /// let header = payload::HeaderBuilder::default()
    ///     .flags(ExchangeFlags::RELIABILITY)
    ///     .protocol_opcode(ProtocolOpCode::Vendor{vendor_id: 0xa1b2, protocol: 0xabcd, opcode: 0x68})
    ///     .exchange(ExchangeId(0xabcd))
    ///     .ack_counter(Some(0x440011aa))
    ///     .build()
    ///     .unwrap();
    ///
    /// let mut buffer = [0u8; 16];
    /// let cnt = {
    ///    let mut writer = SliceLittleEndianWriter::new(buffer.as_mut_slice());
    ///    assert!(header.write(&mut writer).is_ok());
    ///    writer.written()
    /// };
    ///
    /// assert_eq!(cnt, 12);
    /// assert_eq!(buffer.as_slice(), &[
    ///   0x16,                   // flags: Reliability, ACK, VendorProtocol
    ///   0x68,                   // protocol opcode
    ///   0xcd, 0xab,             // Exchange id
    ///   0xcd, 0xab,             // protocol id
    ///   0xb2, 0xa1,             // vendor protocol id
    ///   0xaa, 0x11, 0x00, 0x44, // Ack counter
    ///   // rest of data unchanged
    ///   0, 0, 0, 0, 
    /// ]);
    /// ```
    pub fn write(&self, writer: &mut impl LittleEndianWriter) -> Result<()> {
        let mut flags = self.flags.clone();
        flags.set(ExchangeFlags::VENDOR, matches!(self.protocol_opcode, ProtocolOpCode::Vendor { ..}));
        flags.set(ExchangeFlags::ACKNOWLEDGEMENT, self.ack_counter.is_some());

        writer.write_le_u8(flags.bits())?;
        writer.write_le_u8(self.protocol_opcode.protocol_opcode())?;
        writer.write_le_u16(self.exchange.0)?;
        writer.write_le_u16(self.protocol_opcode.protocol_id())?;
        
        if let ProtocolOpCode::Vendor { vendor_id, ..} = self.protocol_opcode {
            writer.write_le_u16(vendor_id)?;
        }

        if let Some(counter) = self.ack_counter {
            writer.write_le_u32(counter)?;
        }

        Ok(())
    }
}
