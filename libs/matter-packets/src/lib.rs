use std::io::Read;

use anyhow::{Result, anyhow};

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
    pub session_id: u16,
    pub source: Option<NodeId>,
    pub destination: MessageDestination,
}


impl MessageData {
    /// Parses a given buffer and interprets it as a MATTER message.
    /// 
    /// Examples:
    /// 
    /// ```
    /// use matter_packets::{MessageData, MessageDestination, NodeId, GroupId};
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
    ///
    /// let data = MessageData::parse(&[
    ///   0x06,                   // flags: Source node id and destination group
    ///   0x33, 0x22,             // session id: 0x2233
    ///   0x00,                   // security flags
    ///   0x00, 0x00, 0x00, 0x00, // counter
    ///   0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd,  // source node id
    ///   0xcd, 0xab,             // source group id
    /// ]).unwrap();
    /// 
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, Some(NodeId(0xddccbbaa78563412)));
    /// assert_eq!(data.destination, MessageDestination::Group(GroupId(0xabcd)));
    ///
    /// let data = MessageData::parse(&[
    ///   0x01,                   // flags: Destination node id
    ///   0x33, 0x22,             // session id: 0x2233
    ///   0x00,                   // security flags
    ///   0x00, 0x00, 0x00, 0x00, // counter
    ///   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  // destination node id
    /// ]).unwrap();
    /// 
    /// assert_eq!(data.session_id, 0x2233);
    /// assert_eq!(data.source, None);
    /// assert_eq!(data.destination, MessageDestination::Node(NodeId(0x8877665544332211)));
    /// ```
    /// 
    /// 
    pub fn parse(buffer: &[u8]) -> Result<MessageData> {
        let mut buffer = byteordered::ByteOrdered::le(buffer);

        let flags = buffer.read_u8()?;
        
        if flags & FLAGS_VERSION_MASK != FLAGS_VERSION_V1 {
            return Err(anyhow!("Not a valid CHIP v1 message."));
        }

        let session_id = buffer.read_u16()?; // session id
        let _ = buffer.read_u8()?;  // security flags
        let _ = buffer.read_u32()?; // counter

        let source = if flags & FLAGS_SOURCE_NODE_ID_SET != 0 {
            Some(NodeId(buffer.read_u64()?))
        } else {
            None
        };
        
        let destination = match flags & FLAGS_DESTINATION_MASK {
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
