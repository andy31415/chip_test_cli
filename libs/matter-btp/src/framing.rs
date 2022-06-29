use anyhow::{anyhow, Result};
use bitflags::bitflags;
use std::time::Duration;

#[cfg(test)]
use mock_instant::Instant;

#[cfg(not(test))]
use std::time::Instant;

bitflags! {
    /// Represents flags within a BTP header structure
    pub struct HeaderFlags: u8 {
       const SEGMENT_BEGIN = 0b_0000_0001;
       const SEGMENT_END = 0b_0000_0100;
       const CONTAINS_ACK = 0b_0000_1000;
       const MANAGEMENT_MESSAGE = 0b_0010_0000;
       const HANDSHAKE_MESSAGE = 0b_0100_0000;


       const HANDSHAKE_REQUEST =
          Self::HANDSHAKE_MESSAGE.bits |
          Self::MANAGEMENT_MESSAGE.bits |
          Self::SEGMENT_BEGIN.bits |
          Self::SEGMENT_END.bits;

       const HANDSHAKE_RESPONSE =
          Self::HANDSHAKE_MESSAGE.bits |
          Self::MANAGEMENT_MESSAGE.bits |
          Self::SEGMENT_BEGIN.bits |
          Self::SEGMENT_END.bits;
    }
}

#[derive(Debug, PartialEq)]
pub struct BtpDataPacket<'a> {
    pub flags: HeaderFlags,
    pub sequence_info: PacketSequenceInfo,
    pub payload: &'a [u8],
}

impl<'a> BtpDataPacket<'a> {
    /// Parses a given buffer and interprets it as a data packet
    ///
    /// will NOT accept management messages.
    ///
    /// Examples:
    ///
    /// ```
    /// use matter_btp::framing::{BtpDataPacket, HeaderFlags, PacketSequenceInfo};
    ///
    ///
    /// // short messages are rejected
    /// assert!(BtpDataPacket::parse(&[]).is_err());
    /// assert!(BtpDataPacket::parse(&[0]).is_err());
    /// assert!(BtpDataPacket::parse(&[8, 0]).is_err());
    ///
    /// // handshake and management messages are rejected
    /// assert!(BtpDataPacket::parse(&[0x20, 0, 0 ,0]).is_err());
    /// assert!(BtpDataPacket::parse(&[0x40, 0, 0 ,0]).is_err());
    /// assert!(BtpDataPacket::parse(&[0x60, 0, 0 ,0]).is_err());
    ///
    /// let packet = BtpDataPacket::parse(&[8, 0, 2]).unwrap();
    /// assert_eq!(packet.flags, HeaderFlags::CONTAINS_ACK);
    /// assert_eq!(
    ///     packet.sequence_info,
    ///     PacketSequenceInfo{
    ///        ack_number: Some(0),
    ///        sequence_number: 2,
    ///     }
    /// );
    ///
    /// let packet = BtpDataPacket::parse(&[0, 0, 1]).unwrap();
    /// assert_eq!(packet.flags, HeaderFlags::empty());
    /// assert_eq!(
    ///     packet.sequence_info,
    ///     PacketSequenceInfo{
    ///        ack_number: None,
    ///        sequence_number: 0,
    ///     }
    /// );
    /// assert_eq!(packet.payload, &[1]);
    /// ```
    pub fn parse(buffer: &'a [u8]) -> Result<BtpDataPacket<'a>> {
        match buffer {
            [flags, rest @ ..] => {
                let flags =
                    HeaderFlags::from_bits(*flags).ok_or_else(|| anyhow!("Invalid flags"))?;

                if flags
                    .intersects(HeaderFlags::MANAGEMENT_MESSAGE | HeaderFlags::HANDSHAKE_MESSAGE)
                {
                    return Err(anyhow!("Parsing of management packets not supported."));
                }

                match rest {
                    [ack_number, sequence_number, payload @ ..]
                        if flags.contains(HeaderFlags::CONTAINS_ACK) =>
                    {
                        Ok(BtpDataPacket {
                            flags,
                            sequence_info: PacketSequenceInfo {
                                ack_number: Some(*ack_number),
                                sequence_number: *sequence_number,
                            },
                            payload,
                        })
                    }
                    [sequence_number, payload @ ..]
                        if !flags.contains(HeaderFlags::CONTAINS_ACK) =>
                    {
                        Ok(BtpDataPacket {
                            flags,
                            sequence_info: PacketSequenceInfo {
                                ack_number: None,
                                sequence_number: *sequence_number,
                            },
                            payload,
                        })
                    }
                    _ => Err(anyhow!("Invalid message after checking flags")),
                }
            }
            _ => Err(anyhow!("Message too short: no space for flags")),
        }
    }
}

pub trait BtpBuffer {
    fn buffer(&self) -> &[u8];
}

/// Abstract BTP message size, providing some helpful methods
/// over a resizable buffer
#[derive(Clone, Debug, Default)]
pub struct ResizableMessageBuffer {
    data: Vec<u8>,
}

impl ResizableMessageBuffer {
    fn ensure_length(&mut self, len: usize) {
        if self.data.len() < len {
            self.data.resize(len, 0);
        }
    }

    /// Sets a u8 value at a specific index. Resizes the undelying
    /// buffer if needed.
    ///
    /// Example:
    ///
    /// ```
    /// use matter_btp::framing::{ResizableMessageBuffer, BtpBuffer};
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
        self.ensure_length(index + 1);
        self.data[index] = value;
    }

    /// Sets a 16-bit value in little endian format at a specific index.
    /// Resizes the undelying buffer if needed.
    ///
    /// Example:
    ///
    /// ```
    /// use matter_btp::framing::{ResizableMessageBuffer, BtpBuffer};
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

    /// Sets the value within the bufffer, extending if needed.
    ///
    /// Example:
    ///
    /// ```
    /// use matter_btp::framing::{ResizableMessageBuffer, BtpBuffer};
    ///
    /// let mut buffer = ResizableMessageBuffer::default();
    ///
    /// assert_eq!(buffer.buffer(), &[]);
    ///
    /// buffer.set_at(2, &[1,2,3]);
    /// assert_eq!(buffer.buffer(), &[0, 0, 1, 2, 3]);
    ///
    /// buffer.set_at(1, &[4,4]);
    /// assert_eq!(buffer.buffer(), &[0, 4, 4, 2, 3]);
    ///
    /// buffer.set_at(0, &[]);
    /// assert_eq!(buffer.buffer(), &[0, 4, 4, 2, 3]);
    ///
    /// buffer.set_at(0, &[8]);
    /// assert_eq!(buffer.buffer(), &[8, 4, 4, 2, 3]);
    ///
    /// buffer.set_at(0, &[1, 2, 3, 4, 5, 6]);
    /// assert_eq!(buffer.buffer(), &[1, 2, 3, 4, 5, 6]);
    ///
    /// buffer.set_at(5, &[]);
    /// assert_eq!(buffer.buffer(), &[1, 2, 3, 4, 5, 6]);
    ///
    /// buffer.set_at(6, &[]);
    /// assert_eq!(buffer.buffer(), &[1, 2, 3, 4, 5, 6]);
    ///
    /// buffer.set_at(7, &[]);
    /// assert_eq!(buffer.buffer(), &[1, 2, 3, 4, 5, 6, 0]);
    /// ```
    pub fn set_at(&mut self, index: usize, buffer: &[u8]) {
        self.ensure_length(index + buffer.len());
        self.data[index..(index + buffer.len())].copy_from_slice(buffer);
    }
}

impl BtpBuffer for ResizableMessageBuffer {
    fn buffer(&self) -> &[u8] {
        self.data.as_slice()
    }
}

// The maximum amount of time after sending a HandshakeRequest
// to wait for a HandshakeResponse before closing a connection.
//const SESSION_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum amount of time after receipt of a segment before
/// a stand-alone ack MUST be sent.
const ACKNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(15);

/// The timeout to use to send a standalone ACK to the other side.
const ACK_SEND_TIMEOUT: Duration = Duration::from_millis(2500);

/// The maximum amount of time no unique data has been sent over
/// a BTP session before a Central device must close the BTP session.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Represents the state of windowed packets for Btp
#[derive(Debug, PartialEq, Clone)]
pub struct PacketWindowState {
    /// Last time a packet was seen and processed.
    ///
    /// This time represents when last_packet_number was inremented while
    /// the window was completely open.
    last_seen_time: Instant,

    /// Packet number of last seen packet.
    ///
    /// When sending packets, this is the number of the last packet
    /// that was sent
    ///
    /// When receiving, this is the number of the last packet received.
    last_packet_number: u8,

    /// what packet number was acknowledged.
    ///
    /// When sending, this is the packet number that was last acknowledged
    /// by the remote side.
    ///
    /// When receiving, this is the packet number that was acknowledged
    /// to the remote as having been received.
    ack_number: u8,
}

impl Default for PacketWindowState {
    fn default() -> Self {
        Self {
            last_seen_time: Instant::now(),
            last_packet_number: 0xFF,
            ack_number: 0xFF,
        }
    }
}

impl PacketWindowState {
    /// Returns number of packets unacknowledged.
    ///
    /// When sending, this is the packet count sent but not acknowledged.
    /// For receiving, this is the packet count received but without an ack
    /// having been sent to the remote.
    ///
    /// Examples:
    ///
    /// ```
    /// use matter_btp::framing::PacketWindowState;
    ///
    /// let mut state = PacketWindowState::default(); // Starts at 0 packet, unacknowledged
    /// assert_eq!(state.unacknowledged_count(), 0);
    ///
    /// state.next_packet();
    ///
    /// assert_eq!(state.unacknowledged_count(), 1);
    /// assert_eq!(state.mark_latest_ack(), Some(0));
    /// assert_eq!(state.unacknowledged_count(), 0);
    /// ```
    pub fn unacknowledged_count(&self) -> u8 {
        self.last_packet_number.wrapping_sub(self.ack_number)
    }

    // Moves the packet window with one packet forward
    pub fn next_packet(&mut self) {
        if self.last_packet_number == self.ack_number {
            self.last_seen_time = Instant::now();
        }

        self.last_packet_number = self.last_packet_number.wrapping_add(1);
    }

    /// Returns the number of the last unacknowledged packet (if any).
    ///
    /// Will return None if no packets are unacknowledged.
    pub fn mark_latest_ack(&mut self) -> Option<u8> {
        if self.last_packet_number == self.ack_number {
            return None;
        }

        // mark that we are acknowledging this packet now
        self.last_seen_time = Instant::now();
        self.ack_number = self.last_packet_number;
        Some(self.last_packet_number)
    }

    /// Acknowledge the given packet number.
    ///
    /// Returns a failure if ack_number is out side the current ack number
    /// and last packet number.
    pub fn ack_packet(&mut self, ack_number: u8) -> Result<()> {
        let ack_delta = ack_number.wrapping_sub(self.ack_number);
        if ack_delta > self.unacknowledged_count() {
            return Err(anyhow!(
                "Ack number {} out of range [{}..{}]",
                ack_number,
                self.ack_number,
                self.last_packet_number
            ));
        }
        self.ack_number = ack_number;
        self.last_seen_time = Instant::now();

        Ok(())
    }
}

/// Represents a transmission status for a BTP connection.
///
/// BTP connections are managing packets to/from a remote
/// side, while considering open window sizes on each side.
#[derive(Debug, PartialEq, Clone)]
pub struct BtpWindowState {
    /// The negociated window size. This is how many packets
    /// could be in flight without confirmation. The implementation
    /// must ensure that:
    ///    - it never sends more items than this size
    ///    - it must not allow both sides to have their window filled
    ///      without an ACK number in them (deadlock since no ack is
    ///      possible anymore if that happens)
    window_size: u8,

    /// packets sent towards the remote
    sent_packets: PacketWindowState,

    /// Packets received from the remote side
    received_packets: PacketWindowState,
}

#[derive(Debug, PartialEq)]
pub struct PacketSequenceInfo {
    pub sequence_number: u8,
    pub ack_number: Option<u8>,
}

/// Represents the state of sending data using the BTP protocol.
#[derive(Debug, PartialEq)]
pub enum BtpSendData {
    /// Wait before attempting to send. This may occur in the following scenarios:
    ///   - Remote window is full, no send is possible until a receive
    ///   - Sending an empty message (just with an ack) is delayed.
    Wait { duration: Duration },
    /// The message can be sent with the given sequence number and should contain
    /// the given ack.
    Send(PacketSequenceInfo),
}

#[derive(PartialEq, Debug)]
pub enum PacketData {
    HasData,
    None,
}

impl BtpWindowState {
    fn new(window_size: u8) -> Self {
        Self {
            window_size,
            sent_packets: PacketWindowState::default(),
            received_packets: PacketWindowState::default(),
        }
    }

    /// Creates a client window state, initialized as a client-side, post-handshake
    ///
    /// Client characteristics as per spec:
    ///    - the sequence number in the first packet send by the client after handshake
    ///      completion SHALL be 0
    ///    - the first data packet includes the ack for the connect response
    ///
    /// ```
    /// # use matter_btp::framing::*;
    ///
    /// let mut state= BtpWindowState::client(4);
    ///
    /// let info = state.prepare_send(PacketData::HasData).unwrap();
    /// assert_eq!(
    ///    info,
    ///    BtpSendData::Send(
    ///        PacketSequenceInfo{
    ///            sequence_number: 0,
    ///            ack_number: Some(0),
    ///        }
    ///    )
    /// )
    /// ```
    pub fn client(window_size: u8) -> Self {
        let mut result = BtpWindowState::new(window_size);

        // assume packet 0 was received. Packet 0 is the connect response
        result.received_packets.next_packet();

        result
    }

    /// Creates a server window state, initialized as a server-side, post-handshake.
    ///
    /// Servers assume packet 0 has NOT yet been acknowledged.
    ///
    /// Examples:
    ///
    /// ```
    /// # use matter_btp::framing::*;
    ///
    /// let mut state= BtpWindowState::server(4);
    ///
    /// let info = state.prepare_send(PacketData::HasData).unwrap();
    /// assert_eq!(
    ///    info,
    ///    BtpSendData::Send(
    ///        PacketSequenceInfo{
    ///            sequence_number: 1,
    ///            ack_number: None,
    ///        }
    ///    )
    /// )
    /// ```
    ///
    /// ```
    /// # use matter_btp::framing::*;
    ///
    /// let mut state= BtpWindowState::server(4);
    ///
    /// assert!(
    ///    state.packet_received(PacketSequenceInfo{
    ///       sequence_number: 0,
    ///       ack_number: Some(0),
    ///    }).is_ok()
    /// );
    ///
    /// let info = state.prepare_send(PacketData::HasData).unwrap();
    /// assert_eq!(
    ///    info,
    ///    BtpSendData::Send(
    ///        PacketSequenceInfo{
    ///            sequence_number: 1,
    ///            ack_number: Some(0),
    ///        }
    ///    )
    /// )
    /// ```
    pub fn server(window_size: u8) -> Self {
        let mut result = BtpWindowState::new(window_size);
        // move the sent packets forward: packet 0 should be ent (the connection response)
        result.sent_packets.next_packet();

        result
    }

    /// Update the state based on a received packet.
    ///
    /// Will return an error if the internal receive state became inconsistent.
    /// On error, it is expected that the BTP connection is to be terminated.
    pub fn packet_received(&mut self, packet_data: PacketSequenceInfo) -> Result<()> {
        self.received_packets.next_packet();

        if self.received_packets.last_packet_number != packet_data.sequence_number {
            // Packets MUST be monotonically increasing. Error out if they are not
            return Err(anyhow!(
                "Received unexpected sequence numbe {}. Expected {}",
                packet_data.sequence_number,
                self.received_packets.last_packet_number
            ));
        }

        if let Some(ack) = packet_data.ack_number {
            self.sent_packets.ack_packet(ack)?;
        }

        Ok(())
    }

    /// Get send data parameters.
    ///
    /// Returns if a send can/should be performed over the given channel.
    ///
    /// Depending if data is available or not, sending may decide to wait before
    /// sending packets over the wire.
    ///
    /// If sending is delayed (i.e. 'wait' is being returned), re-send should be
    /// attempted whenever a new packet is received (since that may open send windows).
    pub fn prepare_send(&mut self, data: PacketData) -> Result<BtpSendData> {
        if (self.sent_packets.unacknowledged_count() != 0)
            && (self.sent_packets.last_seen_time + IDLE_TIMEOUT < Instant::now())
        {
            // Expect to receive an ack within the given time window
            return Err(anyhow!("Timeout receiving data: no ack received in time"));
        }

        if self.sent_packets.unacknowledged_count() >= self.window_size {
            // The remote side has no window size for packets, cannot send any data
            return Ok(BtpSendData::Wait {
                duration: IDLE_TIMEOUT - (Instant::now() - self.sent_packets.last_seen_time),
            });
        }

        if (self.received_packets.unacknowledged_count() == 0)
            && (self.sent_packets.unacknowledged_count() + 1 == self.window_size)
        {
            // Cannot send yet: no packates to acknowledge and can only send a single packet
            // before the remote is fully closed.
            //
            // In particular this means we will only send the last packet if it can contain an ack.
            return Ok(BtpSendData::Wait {
                duration: IDLE_TIMEOUT - (Instant::now() - self.sent_packets.last_seen_time),
            });
        }

        if (self.received_packets.unacknowledged_count() + 2 < self.window_size)
            && (data == PacketData::None)
        {
            // If sufficient open window remains and data still can be sent, then delay sending any
            // ack for now.
            let time_since_last_sent = Instant::now() - self.sent_packets.last_seen_time;

            if time_since_last_sent < ACK_SEND_TIMEOUT {
                return Ok(BtpSendData::Wait {
                    duration: ACK_SEND_TIMEOUT - time_since_last_sent,
                });
            }
        }

        // If we get up to here, a packet can be sent
        self.sent_packets.next_packet();

        Ok(BtpSendData::Send(PacketSequenceInfo {
            sequence_number: self.sent_packets.last_packet_number,
            ack_number: self.received_packets.mark_latest_ack(),
        }))
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use mock_instant::MockClock;

    use crate::framing::{BtpSendData, BtpWindowState, PacketData, PacketSequenceInfo};

    use super::ACK_SEND_TIMEOUT;

    #[derive(PartialEq)]
    enum SendDirection {
        ClientToServer,
        ServerToClient,
    }

    struct ClientServerPipe {
        client: BtpWindowState,
        server: BtpWindowState,
    }

    impl ClientServerPipe {
        pub(crate) fn new(window_size: u8) -> Self {
            Self {
                client: BtpWindowState::client(window_size),
                server: BtpWindowState::server(window_size),
            }
        }

        pub(crate) fn expect_wait_send(
            &mut self,
            direction: SendDirection,
            data: PacketData,
            duration: Duration,
        ) {
            if direction == SendDirection::ClientToServer {
                ClientServerPipe::expect_wait_send_impl(&mut self.client, data, duration)
            } else {
                ClientServerPipe::expect_wait_send_impl(&mut self.server, data, duration)
            }
        }

        pub(crate) fn expect_send(
            &mut self,
            direction: SendDirection,
            data: PacketData,
            packet: PacketSequenceInfo,
        ) {
            if direction == SendDirection::ClientToServer {
                ClientServerPipe::expect_send_impl(&mut self.client, &mut self.server, data, packet)
            } else {
                ClientServerPipe::expect_send_impl(&mut self.server, &mut self.client, data, packet)
            }
        }

        pub(crate) fn expect_send_impl(
            src: &mut BtpWindowState,
            dst: &mut BtpWindowState,
            data: PacketData,
            packet: PacketSequenceInfo,
        ) {
            match src.prepare_send(data) {
                Ok(BtpSendData::Send(data)) => assert_eq!(data, packet),
                different => assert!(
                    false,
                    "Prepare send should have been {:?} but was {:?} instead",
                    packet, different
                ),
            }

            match dst.packet_received(packet) {
                Ok(_) => {}
                Err(e) => assert!(false, "Failed to accept receiving of {:?}", e),
            }
        }

        pub(crate) fn expect_wait_send_impl(
            state: &mut BtpWindowState,
            data: PacketData,
            expected_duration: Duration,
        ) {
            match state.prepare_send(data) {
                Ok(BtpSendData::Wait { duration }) => assert_eq!(duration, expected_duration),
                different => assert!(
                    false,
                    "Expected a wait of  {:?} but was {:?} instead",
                    expected_duration, different
                ),
            }
        }
    }

    #[test]
    fn btp_window_matches_spec_sample() {
        // this example is the Matter example for BTP interactions for a window size 4
        let mut pipe = ClientServerPipe::new(4);

        // Sufficient window available, do not worry about needing to send acks.
        pipe.expect_wait_send(
            SendDirection::ServerToClient,
            PacketData::None,
            ACK_SEND_TIMEOUT,
        );

        pipe.expect_send(
            SendDirection::ClientToServer,
            PacketData::HasData,
            PacketSequenceInfo {
                sequence_number: 0,
                ack_number: Some(0),
            },
        );

        // Sufficient window available, do not worry about needing to send acks.
        pipe.expect_wait_send(
            SendDirection::ServerToClient,
            PacketData::None,
            ACK_SEND_TIMEOUT,
        );
        pipe.expect_wait_send(
            SendDirection::ClientToServer,
            PacketData::None,
            ACK_SEND_TIMEOUT,
        );

        pipe.expect_send(
            SendDirection::ClientToServer,
            PacketData::HasData,
            PacketSequenceInfo {
                sequence_number: 1,
                ack_number: None,
            },
        );

        // only 2 window slots remain, send ack early
        pipe.expect_send(
            SendDirection::ServerToClient,
            PacketData::None,
            PacketSequenceInfo {
                sequence_number: 1,
                ack_number: Some(1),
            },
        );

        pipe.expect_send(
            SendDirection::ClientToServer,
            PacketData::HasData,
            PacketSequenceInfo {
                sequence_number: 2,
                ack_number: Some(1),
            },
        );

        pipe.expect_wait_send(
            SendDirection::ServerToClient,
            PacketData::None,
            ACK_SEND_TIMEOUT,
        );
        MockClock::advance(Duration::from_secs(1));

        pipe.expect_wait_send(
            SendDirection::ServerToClient,
            PacketData::None,
            ACK_SEND_TIMEOUT - Duration::from_secs(1),
        );
        MockClock::advance(ACK_SEND_TIMEOUT - Duration::from_secs(1));

        pipe.expect_send(
            SendDirection::ServerToClient,
            PacketData::None,
            PacketSequenceInfo {
                sequence_number: 2,
                ack_number: Some(2),
            },
        );

        // Connection is in idle state ... client side also waits
        pipe.expect_wait_send(
            SendDirection::ClientToServer,
            PacketData::None,
            ACK_SEND_TIMEOUT,
        );
    }
}
