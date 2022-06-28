use crate::framing::HeaderFlags;
use anyhow::{anyhow, Result};

// a nibble really
const BTP_PROTOCOL_VERSION: u8 = 0x04;
const MANAGEMENT_OPCODE: u8 = 0x6C;

pub trait BtpBuffer {
    fn buffer(&self) -> &[u8];
}

/// Abstract BTP message size, providing some helpful methods
/// over a resizable buffer
#[derive(Clone, Debug, Default)]
pub struct ResizableMessageBuffer {
    data: Vec<u8>,
    data_len: usize,
}

impl ResizableMessageBuffer {
    /// Sets a u8 value at a specific index. Resizes the undelying
    /// buffer if needed.
    /// 
    /// Example:
    /// 
    /// ```
    /// use matter_btp::handshake::{ResizableMessageBuffer, BtpBuffer};
    /// 
    /// let mut buffer = ResizableMessageBuffer::default();
    /// 
    /// assert_eq!(buffer.buffer(), &[]);
    ///
    /// buffer.set_u8(0, 3);
    /// assert_eq!(buffer.buffer(), &[3]);
    ///
    /// buffer.set_u8(3, 10);
    /// assert_eq!(buffer.buffer(), &[3, 0, 0, 10]);
    ///
    /// buffer.set_u8(0, 11);
    /// assert_eq!(buffer.buffer(), &[11, 0, 0, 10]);
    /// ```
    pub fn set_u8(&mut self, index: usize, value: u8) {
        if self.data.len() < index + 1 {
            self.data.resize(index + 1, 0);
        }

        if self.data_len < index + 1 {
            self.data_len = index + 1;
        }
        self.data[index] = value;
    }

    /// Sets a 16-bit value in little endian format at a specific index. 
    /// Resizes the undelying buffer if needed.
    /// 
    /// Example:
    /// 
    /// ```
    /// use matter_btp::handshake::{ResizableMessageBuffer, BtpBuffer};
    /// 
    /// let mut buffer = ResizableMessageBuffer::default();
    /// 
    /// assert_eq!(buffer.buffer(), &[]);
    ///
    /// buffer.set_u8(0, 3);
    /// assert_eq!(buffer.buffer(), &[3]);
    ///
    /// buffer.set_u16(0, 10);
    /// assert_eq!(buffer.buffer(), &[10, 0]);
    ///
    /// buffer.set_u16(1, 0x1234);
    /// assert_eq!(buffer.buffer(), &[10, 0x34, 0x12]);
    ///
    /// buffer.set_u16(5, 0x6655);
    /// assert_eq!(buffer.buffer(), &[10, 0x34, 0x12, 0, 0, 0x55, 0x66]);
    /// ```
    pub fn set_u16(&mut self, index: usize, value: u16) {
        let h = ((value >> 8) & 0xFF) as u8;
        let l = (value & 0xFF) as u8;

        self.set_u8(index + 1, h);
        self.set_u8(index, l);
    }
}

impl BtpBuffer for ResizableMessageBuffer {
    fn buffer(&self) -> &[u8] {
        self.data.split_at(self.data_len).0
    }
}

// Represents a handshake request
#[derive(Clone, Debug)]
pub struct Request {
    buffer: ResizableMessageBuffer,
}

impl Default for Request {
    fn default() -> Self {
        let mut request = Self {
            buffer: Default::default(),
        };

        request
            .buffer
            .set_u8(0, HeaderFlags::HANDSHAKE_REQUEST.bits());
        request.buffer.set_u8(1, MANAGEMENT_OPCODE);

        // Only one protocol supported, so no array of versions here, just one
        // Note that the LOW NIBBLE is the important one
        request.buffer.set_u8(2, BTP_PROTOCOL_VERSION);

        // sets the client window size to 0, to force internal buffer resizing
        request.buffer.set_u8(8, 0);
        
        // now set some maybe valid minimal sizes
        request.set_window_size(8);
        request.set_segment_size(20);

        request
    }
}

impl Request {
    pub fn set_segment_size(&mut self, size: u16) {
        self.buffer.set_u16(6, size);
    }

    pub fn set_window_size(&mut self, size: u8) {
        self.buffer.set_u8(8, size);
    }
}

impl BtpBuffer for Request {
    /// Gets the underlying buffer value after a Request is set up
    /// 
    /// Example:
    ///
    /// ```
    /// use matter_btp::handshake::{Request, BtpBuffer};
    /// 
    /// let mut request = Request::default();
    /// 
    /// request.set_window_size(21);
    /// request.set_segment_size(1234);
    /// 
    /// assert_eq!(
    ///     request.buffer(),
    ///     &[
    ///        0x65,                   // H,M,E,B are all set
    ///        0x6C,                   // Management opcode
    ///        0x04, 0x00, 0x00, 0x00, // version 4 in low bits, 0 in the rest of version choices
    ///        0xd2, 0x04,             // segment size
    ///        21                      // window size
    ///     ]
    /// );
    /// ```
    fn buffer(&self) -> &[u8] {
        self.buffer.buffer()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Response {
    pub selected_segment_size: u16,
    pub selected_window_size: u8,
}

impl Response {
    /// Parses a buffer representing a handshake response.
    ///
    /// Example:
    ///
    /// ```
    /// use matter_btp::handshake::Response;
    ///
    ///
    /// assert!(Response::parse(&[]).is_err());
    /// assert!(Response::parse(&[0]).is_err());
    /// 
    /// assert_eq!(
    ///     Response::parse(&[
    ///        0x65,                   // H,M,E,B are all set
    ///        0x6C,                   // Management opcode
    ///        0x04,                   // selected protocol (4)
    ///        0xd2, 0x04,             // segment size
    ///        21                      // window size
    ///     ]).unwrap(),
    ///     Response{
    ///        selected_segment_size: 1234,
    ///        selected_window_size: 21,
    ///     }
    /// );
    ///
    /// assert!(
    ///     Response::parse(&[
    ///        0x65,                   // H,M,E,B are all set
    ///        0x6C,                   // Management opcode
    ///        0x05,                   // INVALID PROTOCOL
    ///        0xd2, 0x04,             // segment size
    ///        21                      // window size
    ///     ]).is_err()
    /// );
    /// ```
    pub fn parse(buffer: &[u8]) -> Result<Response> {
        match buffer {
            [flags, opcode, protocol, segment_l, segment_h, window_size] => {
                if *flags != HeaderFlags::HANDSHAKE_RESPONSE.bits() {
                    return Err(anyhow!("Invalid response flags: 0x{:X}", flags));
                }

                if *opcode != MANAGEMENT_OPCODE {
                    return Err(anyhow!("Invalid management opcode: 0x{:X}", opcode));
                }

                // technically we should only look at low bits, but then reserved should be 0 anyway
                if *protocol != BTP_PROTOCOL_VERSION {
                    return Err(anyhow!("Invalid protocol: 0x{:X}", protocol));
                }

                Ok(Response {
                    selected_segment_size: ((*segment_h as u16) << 8) | (*segment_l as u16),
                    selected_window_size: *window_size,
                })
            }
            _ => Err(anyhow!(
                "Invalid data length. Expected 6, got {} instead.",
                buffer.len()
            )),
        }
    }
}
