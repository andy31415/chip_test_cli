#![feature(slice_take)]

pub mod reader;
pub mod packet_header;

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


// TODO: protocol header

// CHIP Protocol format:
// - u8:    Exchange flags
// - u8:    Protocol Opcode: depends on opcode for protocol
// - u16:   Exchange ID
// - u16:   Protocol ID:     0 == secure channel, 1 == IM, 2 == BDX, 3 == User Directed Commissioning
// - [u16]: Protocol Vendor Id
// - [u32]: Ack Counter
// - ???: extensions (secured) - based on flag: length (u16) + data
// - ???: payload
