use anyhow::{anyhow, Result};
use byteorder::ByteOrder;

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
pub struct MessageData {
    pub flags: SecurityFlags,
    pub session_id: u16,
    pub source: Option<NodeId>,
    pub destination: MessageDestination,
    pub counter: u32,
}

impl MessageData {
    /// Parses a given buffer and interprets it as a MATTER message.
    ///
    /// Examples:
    ///
    /// ```
    /// use matter_packets::*;
    ///
    /// // invalid messages are rejected
    /// assert!(MessageData::parse(&[]).is_err()); // too short
    /// assert!(MessageData::parse(&[0, 0, 0]).is_err()); // too short
    /// assert!(MessageData::parse(&[0x11, 0, 0, 0, 0, 0, 0, 0]).is_err()); // invalid version
    ///
    /// let data = MessageData::parse(&[
    ///   0x00,                   // flags: none set
    ///   0x34, 0x12,             // session id: 0x1234
    ///   0x00,                   // security flags
    ///   0x00, 0x00, 0x00, 0x00, // counter
    /// ]).unwrap();
    ///
    /// assert_eq!(data.session_id, 0x1234);
    /// assert_eq!(data.source, None);
    /// assert_eq!(data.destination, MessageDestination::None);
    /// assert_eq!(data.flags.session_type().unwrap(), SessionType::Unicast);
    ///
    /// let data = MessageData::parse(&[
    ///   0x06,                   // flags: Source node id and destination group
    ///   0x33, 0x22,             // session id: 0x2233
    ///   0x01,                   // security flags
    ///   0x01, 0x00, 0x00, 0x00, // counter
    ///   0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd,  // source node id
    ///   0xcd, 0xab,             // destination group id
    /// ]).unwrap();
    ///
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, Some(NodeId(0xddccbbaa78563412)));
    /// assert_eq!(data.destination, MessageDestination::Group(GroupId(0xabcd)));
    /// assert_eq!(data.counter, 1);
    /// assert_eq!(data.flags.session_type().unwrap(), SessionType::GroupMulticast);
    ///
    /// let data = MessageData::parse(&[
    ///   0x01,                   // flags: Destination node id
    ///   0x33, 0x22,             // session id: 0x2233
    ///   0x00,                   // security flags
    ///   0x45, 0x23, 0x01, 0x00, // counter
    ///   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  // destination node id
    /// ]).unwrap();
    ///
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, None);
    /// assert_eq!(data.destination, MessageDestination::Node(NodeId(0x8877665544332211)));
    /// assert_eq!(data.counter, 0x12345);
    /// ```
    ///
    ///
    pub fn parse(buffer: &[u8]) -> Result<MessageData> {
        let mut buffer = byteordered::ByteOrdered::le(buffer);

        let message_flags = buffer.read_u8()?;

        if message_flags & FLAGS_VERSION_MASK != FLAGS_VERSION_V1 {
            return Err(anyhow!("Not a valid CHIP v1 message."));
        }

        let session_id = buffer.read_u16()?; // session id
        let flags = SecurityFlags::from_bits(buffer.read_u8()?)
            .ok_or_else(|| anyhow!("Invalid security flags"))?;

        // this makes sure session flags are valid
        flags.session_type()?;

        let counter = buffer.read_u32()?;

        let source = if message_flags & FLAGS_SOURCE_NODE_ID_SET != 0 {
            Some(NodeId(buffer.read_u64()?))
        } else {
            None
        };

        let destination = match message_flags & FLAGS_DESTINATION_MASK {
            FLAGS_DESTINATION_NODE => MessageDestination::Node(NodeId(buffer.read_u64()?)),
            FLAGS_DESTINATION_GROUP => MessageDestination::Group(GroupId(buffer.read_u16()?)),
            _ => MessageDestination::None,
        };

        // TODO:
        //   - skip extensions if any
        //   - grab payload
        //   - consider MIC
        //
        Ok(MessageData {
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

#[derive(Debug, PartialEq)]
pub enum EndianReadError {
    InsufficientData,
}

/// Allows reading little endian data and provides a
/// method to fetch the 'reminder of the data'
pub trait LittleEndianReader {
    type ReminderType;

    /// Get the next byte, advance iterator.
    fn read_u8(&mut self) -> core::result::Result<u8, EndianReadError>;
    fn read_u16(&mut self) -> core::result::Result<u16, EndianReadError>;
    fn read_u32(&mut self) -> core::result::Result<u32, EndianReadError>;
    fn read_u64(&mut self) -> core::result::Result<u64, EndianReadError>;

    /// Returns the reminder of the data, consuming self
    fn rest(self) -> Self::ReminderType;
}

/// Wraps a `&[u8]` value for reading little endian data
/// out of it via `LittleEndianReader`
///
/// Example:
/// 
/// ```
/// use matter_packets::{LittleEndianReader, ConstU8LittleEndianReader};
/// 
/// let mut reader = ConstU8LittleEndianReader::new(&[1,2,3,4,5,6]);
/// assert_eq!(reader.read_u8(), Ok(1));
/// assert_eq!(reader.read_u16(), Ok(0x0302));
/// assert_eq!(reader.rest(), &[4,5,6]);
/// ```
pub struct ConstU8LittleEndianReader<'a> {
    data: &'a [u8],
}

impl<'a> ConstU8LittleEndianReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn consume(&mut self, count: usize) -> core::result::Result<&'a [u8], EndianReadError> {
        if self.data.len() < count {
            return Err(EndianReadError::InsufficientData);
        }

        let (head, tail) = self.data.split_at(count);
        self.data = tail;

        Ok(head)
    }
}

impl<'a> LittleEndianReader for ConstU8LittleEndianReader<'a> {
    type ReminderType = &'a [u8];

    fn read_u8(&mut self) -> core::result::Result<u8, EndianReadError> {
        Ok(self.consume(1)?[0])
    }

    fn read_u16(&mut self) -> core::result::Result<u16, EndianReadError> {
        Ok(byteorder::LittleEndian::read_u16(self.consume(2)?))
    }

    fn read_u32(&mut self) -> core::result::Result<u32, EndianReadError> {
        Ok(byteorder::LittleEndian::read_u32(self.consume(4)?))
    }

    fn read_u64(&mut self) -> core::result::Result<u64, EndianReadError> {
        Ok(byteorder::LittleEndian::read_u64(self.consume(8)?))
    }

    fn rest(self) -> Self::ReminderType {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_parse_data() {
        let data = &[
            1, 0x11, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let mut reader = ConstU8LittleEndianReader::new(data);

        assert_eq!(reader.read_u8(), Ok(1));
        assert_eq!(reader.read_u16(), Ok(0x1211));
        assert_eq!(reader.read_u64(), Ok(0x0807060504030201));
        assert!(reader.read_u8().is_err());

        let mut reader = ConstU8LittleEndianReader::new(data);
        assert_eq!(reader.read_u32(), Ok(0x01121101));
        assert_eq!(reader.rest(), &[0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }
}
