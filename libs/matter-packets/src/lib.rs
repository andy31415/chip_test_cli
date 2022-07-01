#![feature(slice_take)]

use anyhow::{anyhow, Result};

pub mod reader;

#[repr(u8)]
pub enum Protocols {
    SecureChannel = 0,
    InteractionModel = 1,
    Bdx = 2,
    UserDirectedCommissioning = 3,
}

#[repr(u8)]
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

#[repr(u8)]
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

#[repr(u8)]
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

#[repr(u8)]
pub enum UserDirectedCommissioningOpcode {
    IdentificationDeclaration = 0x00,
}

/// Uniquely identifies a node in a matter fabric
#[derive(Debug, PartialEq)]
pub struct NodeId(pub u64);

/// Uniquely identifies a group in a matter fabric
#[derive(Debug, PartialEq)]
pub struct GroupId(pub u16);

#[derive(Debug, PartialEq)]
pub enum MessageDestination {
    None,
    Node(NodeId),
    Group(GroupId),
}

impl Default for MessageDestination {
    fn default() -> Self {
        MessageDestination::None
    }
}

// Mask and constant for messages version V1
const FLAGS_VERSION_MASK: u8 = 0xF0;
const FLAGS_VERSION_V1: u8 = 0x00;

// bitflag for source node ID being set in a buffer
const FLAGS_SOURCE_NODE_ID_SET: u8 = 0x04;

// mask and constants for destination node if being set in a buffer
const FLAGS_DESTINATION_MASK: u8 = 0x03;
const FLAGS_DESTINATION_NODE: u8 = 0x01;
const FLAGS_DESTINATION_GROUP: u8 = 0x02;

#[derive(Debug, PartialEq)]
pub enum SessionType {
    Unicast,
    GroupMulticast,
}

bitflags::bitflags! {
    /// Represents security flags within the message header
    pub struct SecurityFlags: u8 {
       const PRIVACY = 0b_1000_0000;
       const CONTROL_MESSAGE    = 0b_0100_0000;
       const MESSAGE_EXTENSIONS = 0b_0010_0000;

       // NOTE: this is a BITFIELD of 2 bits, however v1 does
       //       not define actual bits anyway
       const SESSION_TYPE_BIT1 = 0b_0000_0001;
       const SESSION_TYPE_BIT2 = 0b_0000_0010;
       const SESSION_TYPE_MASK = 0b_0000_0011;
    }
}

impl Default for SecurityFlags {
    fn default() -> Self {
        SecurityFlags::empty()
    }
}

impl SecurityFlags {
    pub fn session_type(&self) -> Result<SessionType> {
        match self.bits() & SecurityFlags::SESSION_TYPE_MASK.bits() {
            0 => Ok(SessionType::Unicast),
            1 => Ok(SessionType::GroupMulticast),
            n => Err(anyhow!("Invalid session type {}", n)),
        }
    }
}

/// Represents a message header with data contained in it
///
/// # Binary layout
///
/// | Size           | Description                                                    |
/// |----------------|----------------------------------------------------------------|
/// | `u8`           | Flags: high nibble version, low nibble source/dest flags       |
/// | `u16`          | session id                                                     |
/// | `u8`           | security flags: Privacy/control/Extensions/type                |
/// | `u32`          | counter                                                        |
/// | `0/u64`        | (Optional) Source Node Id                                      |
/// | `0/u16/u64`    | (Optional) Source Group/Node Id                                |
/// | `u16 + (len)`  | (Optional) u16-length prefixed extensions                      |
/// | *              | Payload                                                        |
/// | `16 bytes`     | (Optional) Message Integrity Check (for all except unecrypted) |
///
#[derive(Debug, Default, PartialEq)]
pub struct MessageHeader {
    pub flags: SecurityFlags,
    pub session_id: u16,
    pub source: Option<NodeId>,
    pub destination: MessageDestination,
    pub counter: u32,
}

impl MessageHeader {
    /// Parses a given buffer and interprets it as a MATTER message.
    ///
    /// Examples:
    ///
    /// ```
    /// use matter_packets::*;
    ///
    /// // invalid messages are rejected
    /// let mut data: &[u8] = &[]; // too short
    /// assert!(MessageHeader::parse(&mut data).is_err()); // too short
    ///
    /// let mut data: &[u8] = &[0, 0, 0]; // too short
    /// assert!(MessageHeader::parse(&mut data).is_err()); // too short
    ///
    /// let mut data: &[u8] = &[0x11, 0, 0, 0, 0, 0, 0, 0, 0]; // invalid version
    /// assert!(MessageHeader::parse(&mut data).is_err());
    ///
    /// let mut data: &[u8] = &[
    ///   0x00,                   // flags: none set
    ///   0x34, 0x12,             // session id: 0x1234
    ///   0x00,                   // security flags
    ///   0x00, 0x00, 0x00, 0x00, // counter
    ///   0xaa, 0xbb, 0xcc        // payload
    /// ];
    /// let parsed = MessageHeader::parse(&mut data).unwrap();
    ///
    /// assert_eq!(parsed.session_id, 0x1234);
    /// assert_eq!(parsed.source, None);
    /// assert_eq!(parsed.destination, MessageDestination::None);
    /// assert_eq!(parsed.flags.session_type().unwrap(), SessionType::Unicast);
    /// assert_eq!(data, &[0xaa, 0xbb, 0xcc]);
    ///
    /// let mut data: &[u8] = &[
    ///   0x06,                   // flags: Source node id and destination group
    ///   0x33, 0x22,             // session id: 0x2233
    ///   0x01,                   // security flags
    ///   0x01, 0x00, 0x00, 0x00, // counter
    ///   0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd,  // source node id
    ///   0xcd, 0xab,             // destination group id
    /// ];
    /// let data = MessageHeader::parse(&mut data).unwrap();
    ///
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, Some(NodeId(0xddccbbaa78563412)));
    /// assert_eq!(data.destination, MessageDestination::Group(GroupId(0xabcd)));
    /// assert_eq!(data.counter, 1);
    /// assert_eq!(data.flags.session_type().unwrap(), SessionType::GroupMulticast);
    ///  
    /// let mut data: &[u8] = &[
    ///   0x01,                   // flags: Destination node id
    ///   0x33, 0x22,             // session id: 0x2233
    ///   0x00,                   // security flags
    ///   0x45, 0x23, 0x01, 0x00, // counter
    ///   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  // destination node id
    /// ];
    /// let data = MessageHeader::parse(&mut data).unwrap();
    ///
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, None);
    /// assert_eq!(data.destination, MessageDestination::Node(NodeId(0x8877665544332211)));
    /// assert_eq!(data.counter, 0x12345);
    /// ```
    ///
    ///
    pub fn parse(buffer: &mut impl reader::LittleEndianReader) -> Result<MessageHeader> {
        let message_flags = buffer.read_le_u8()?;

        if message_flags & FLAGS_VERSION_MASK != FLAGS_VERSION_V1 {
            return Err(anyhow!("Not a valid CHIP v1 message."));
        }

        let session_id = buffer.read_le_u16()?; // session id
        let flags = SecurityFlags::from_bits(buffer.read_le_u8()?)
            .ok_or_else(|| anyhow!("Invalid security flags"))?;

        // this makes sure session flags are valid
        flags.session_type()?;

        let counter = buffer.read_le_u32()?;

        let source = if message_flags & FLAGS_SOURCE_NODE_ID_SET != 0 {
            Some(NodeId(buffer.read_le_u64()?))
        } else {
            None
        };

        let destination = match message_flags & FLAGS_DESTINATION_MASK {
            FLAGS_DESTINATION_NODE => MessageDestination::Node(NodeId(buffer.read_le_u64()?)),
            FLAGS_DESTINATION_GROUP => MessageDestination::Group(GroupId(buffer.read_le_u16()?)),
            _ => MessageDestination::None,
        };

        // TODO:
        //   - skip extensions if any
        //   - grab payload
        //   - consider MIC
        //
        Ok(MessageHeader {
            session_id,
            source,
            destination,
            flags,
            counter,
        })
    }
}

// CHIP Protocol format:
// - u8:    Exchange flags
// - u8:    Protocol Opcode: depends on opcode for protocol
// - u16:   Exchange ID
// - u16:   Protocol ID:     0 == secure channel, 1 == IM, 2 == BDX, 3 == User Directed Commissioning
// - [u16]: Protocol Vendor Id
// - [u32]: Ack Counter
// - ???: extensions (secured) - based on flag: length (u16) + data
// - ???: payload
