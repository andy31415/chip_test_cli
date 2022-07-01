use std::{error::Error, fmt::Display};

use matter_types::{VendorId, ExchangeId};
use anyhow::{Result, anyhow};

use crate::reader::LittleEndianReader;

/// an error when parsing a protocol
#[derive(PartialEq, Debug)]
pub enum ProtocolOpCodeError {
    UnknownProtocolId,
    UnknownOpCode,
}

impl Display for ProtocolOpCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolOpCodeError::UnknownProtocolId => f.write_str("Unknown protocol id"),
            ProtocolOpCodeError::UnknownOpCode => f.write_str("Unknown protocol opcode"),
        }
    }
}

impl Error for ProtocolOpCodeError{}

/// Opcodes specific to secure channel
#[repr(u8)]
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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

#[derive(PartialEq, Debug)]
pub enum ProtocolOpCode {
    SecureChannel(SecureChannelOpcode),
    InteractionModel(InteractionModelOpcode),
    Bdx(BdxOpcode),
    UserDirectedCommissioning(UserDirectedCommissioningOpcode)
}

impl ProtocolOpCode {
    /// Return the underlying protocol id for the given opcode
    pub fn protocol_id(&self) -> u8 {
        match self {
            ProtocolOpCode::SecureChannel(_) => 0,
            ProtocolOpCode::InteractionModel(_) => 1,
            ProtocolOpCode::Bdx(_) => 2,
            ProtocolOpCode::UserDirectedCommissioning(_) => 3,
        }
    }
    
    /// parse a tuple of protocol id and opcode id and return the underlying known opcode value.
    pub fn from_id_and_opcode(protocol_id: u8, opcode: u8) -> Result<ProtocolOpCode, ProtocolOpCodeError> {
        match protocol_id {
            0 => Ok(ProtocolOpCode::SecureChannel(SecureChannelOpcode::try_from(opcode)?)),
            1 => Ok(ProtocolOpCode::InteractionModel(InteractionModelOpcode::try_from(opcode)?)),
            2 => Ok(ProtocolOpCode::Bdx(BdxOpcode::try_from(opcode)?)),
            3 => Ok(ProtocolOpCode::UserDirectedCommissioning(UserDirectedCommissioningOpcode::try_from(opcode)?)),
            _ => Err(ProtocolOpCodeError::UnknownProtocolId)
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
///
pub struct Header {
   pub flags: ExchangeFlags,
   pub protocol_opcode: ProtocolOpCode, /// contains both protocol id and opcode
   pub exchange: ExchangeId,
   pub vendor_id: Option<VendorId>,
   pub ack_counter: Option<u32>
}


impl Header {
    /// Parses a given buffer and interprets it as a MATTER message.
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
    /// ```
    ///
    ///
    pub fn parse(buffer: &mut impl LittleEndianReader) -> Result<Header> {
        let flags = ExchangeFlags::from_bits(buffer.read_le_u8()?).ok_or_else(|| anyhow!("Invalid exchange flags"))?;
        let opcode = buffer.read_le_u8()?;
        let exchange = ExchangeId(buffer.read_le_u16()?);
        let protocol = buffer.read_le_u8()?;
        
        
        let vendor_id = if flags.contains(ExchangeFlags::VENDOR)  {
            Some(VendorId(buffer.read_le_u16()?))
        } else {
            None
        };
        
        let ack_counter = if flags.contains(ExchangeFlags::ACKNOWLEDGEMENT) {
            Some(buffer.read_le_u32()?)
        } else {
            None
        };

        Ok(Header{
            flags,
            protocol_opcode: ProtocolOpCode::from_id_and_opcode(protocol, opcode)?,
            exchange,
            vendor_id,
            ack_counter,
        })
    }
}