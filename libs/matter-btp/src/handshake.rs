use crate::framing::{BtpBuffer, HeaderFlags};
use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};

// a nibble really
const BTP_PROTOCOL_VERSION: u8 = 0x04;
const MANAGEMENT_OPCODE: u8 = 0x6C;

// Represents a handshake request
#[derive(Clone, Debug)]
pub struct Request {
    buffer: [u8; 9],
}

impl Default for Request {
    fn default() -> Self {
        Self {
            #[rustfmt::skip]
            buffer: [
                HeaderFlags::HANDSHAKE_REQUEST.bits(),
                MANAGEMENT_OPCODE,
                BTP_PROTOCOL_VERSION, 0, 0, 0, // No other versions
                20, 0,                         // minimal segment size
                4,                             // small window size
            ],
        }
    }
}

impl Request {
    pub fn set_segment_size(&mut self, size: u16) {
        LittleEndian::write_u16(&mut self.buffer[6..8], size);
    }

    pub fn set_window_size(&mut self, size: u8) {
        self.buffer[8] = size;
    }
}

impl BtpBuffer for Request {
    /// Gets the underlying buffer value after a Request is set up
    ///
    /// Example:
    ///
    /// ```
    /// use matter_btp::framing::BtpBuffer;
    /// use matter_btp::handshake::Request;
    ///
    /// let mut request = Request::default();
    ///
    /// assert_eq!(
    ///     request.buffer(),
    ///     &[
    ///        0x65,                   // H,M,E,B are all set
    ///        0x6C,                   // Management opcode
    ///        0x04, 0x00, 0x00, 0x00, // version 4 in low bits, 0 in the rest of version choices
    ///        20, 0,                  // segment size
    ///        4                       // window size
    ///     ]
    /// );
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
        self.buffer.as_slice()
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
