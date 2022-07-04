use anyhow::{anyhow, Result};
use derive_builder::Builder;
use matter_types::{GroupId, NodeId};

use super::reader::LittleEndianReader;
use crate::writer::LittleEndianWriter;

#[derive(Debug, PartialEq, Clone, Copy)]
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
#[derive(Debug, Default, PartialEq, Builder)]
pub struct Header {
    pub flags: SecurityFlags,
    pub session_id: u16,

    #[builder(default)]
    pub source: Option<NodeId>,

    #[builder(default)]
    pub destination: MessageDestination,
    pub counter: u32,
}

impl Header {
    /// Parses a given buffer and interprets it as a MATTER message.
    ///
    /// NOTE:
    ///   [SecurityFlags::MESSAGE_EXTENSIONS] is NOT processed (i.e. the extensions
    ///   are not skipped as part of parsing the header) and should be skipped or
    ///   interpreted separately.
    ///
    /// Examples:
    ///
    /// ```
    /// use matter_types::*;
    /// use matter_packets::packet::*;
    ///
    /// // invalid messages are rejected
    /// let mut data: &[u8] = &[]; // too short
    /// assert!(Header::parse(&mut data).is_err()); // too short
    ///
    /// let mut data: &[u8] = &[0, 0, 0]; // too short
    /// assert!(Header::parse(&mut data).is_err()); // too short
    ///
    /// let mut data: &[u8] = &[0x11, 0, 0, 0, 0, 0, 0, 0, 0]; // invalid version
    /// assert!(Header::parse(&mut data).is_err());
    ///
    /// let mut data: &[u8] = &[
    ///   0x00,                   // flags: none set
    ///   0x34, 0x12,             // session id: 0x1234
    ///   0x00,                   // security flags
    ///   0x00, 0x00, 0x00, 0x00, // counter
    ///   0xaa, 0xbb, 0xcc        // payload
    /// ];
    /// let parsed = Header::parse(&mut data).unwrap();
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
    /// let data = Header::parse(&mut data).unwrap();
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
    /// let data = Header::parse(&mut data).unwrap();
    ///
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, None);
    /// assert_eq!(data.destination, MessageDestination::Node(NodeId(0x8877665544332211)));
    /// assert_eq!(data.counter, 0x12345);
    /// ```
    ///
    ///
    pub fn parse(buffer: &mut impl LittleEndianReader) -> Result<Header> {
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

        Ok(Header {
            session_id,
            source,
            destination,
            flags,
            counter,
        })
    }

    /// Serialize a header into some write destination.
    ///
    /// # Examples:
    ///
    /// ```
    /// use matter_packets::packet::{Header, HeaderBuilder, SecurityFlags};
    /// use matter_packets::writer::{LittleEndianWriter, SliceLittleEndianWriter};
    ///
    /// let header = HeaderBuilder::default()
    ///           .session_id(123)
    ///           .counter(0x11223344)
    ///           .flags(SecurityFlags::PRIVACY)
    ///           .build()
    ///           .unwrap();
    ///
    /// let mut buffer = [0u8; 16];
    /// let cnt = {
    ///    let mut writer = SliceLittleEndianWriter::new(buffer.as_mut_slice());
    ///    assert!(header.write(&mut writer).is_ok());
    ///    writer.written()
    /// };
    ///
    /// assert_eq!(cnt, 8);
    /// assert_eq!(buffer.as_slice(), &[
    ///   0x00,                   // flags: none
    ///   123, 0,                 // session id: 0x2233
    ///   0x80,                   // security flags: PRIVACY
    ///   0x44, 0x33, 0x22, 0x11, // counter
    ///   0, 0, 0, 0, 0, 0, 0, 0  // rest of the buffer stays unwritten
    /// ]);
    /// ```
    pub fn write(&self, writer: &mut impl LittleEndianWriter) -> Result<()> {
        let message_flags = FLAGS_VERSION_V1
            | match self.source {
                Some(_) => FLAGS_SOURCE_NODE_ID_SET,
                None => 0,
            }
            | match self.destination {
                MessageDestination::Node(_) => FLAGS_DESTINATION_NODE,
                MessageDestination::Group(_) => FLAGS_DESTINATION_GROUP,
                MessageDestination::None => 0,
            };

        writer.write_le_u8(message_flags)?;
        writer.write_le_u16(self.session_id)?;
        writer.write_le_u8(self.flags.bits())?;
        writer.write_le_u32(self.counter)?;

        if let Some(NodeId(id)) = self.source {
            writer.write_le_u64(id)?;
        }

        match self.destination {
            MessageDestination::Node(NodeId(id)) => writer.write_le_u64(id)?,
            MessageDestination::Group(GroupId(id)) => writer.write_le_u16(id)?,
            MessageDestination::None => {}
        };

        // NOTE: this does NOT write the extensions

        Ok(())
    }
}
