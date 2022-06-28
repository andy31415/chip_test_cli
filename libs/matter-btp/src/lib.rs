use std::pin::Pin;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bitflags::bitflags;
use btleplug::api::Characteristic;
use btleplug::api::{Peripheral, ValueNotification, WriteType};

use futures::{Stream, StreamExt};
use log::{debug, info, warn};
use tokio::sync::Mutex;

#[cfg(test)]
use mock_instant::Instant;

#[cfg(not(test))]
use std::time::Instant;

// The maximum amount of time after sending a HandshakeRequest
// to wait for a HandshakeResponse before closing a connection.
//const SESSION_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum amount of time after receipt of a segment before
/// a stand-alone ack MUST be sent.
const ACKNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(15);

/// The maximum amount of time no unique data has been sent over
/// a BTP session before a Central device must close the BTP session.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Represents the state of windowed packets for Btp
#[derive(Debug, PartialEq)]
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
    /// # use matter_btp::PacketWindowState;
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
#[derive(Debug, PartialEq)]
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
    /// # use matter_btp::*;
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
    /// # use matter_btp::*;
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
    /// # use matter_btp::*;
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

            if time_since_last_sent < ACKNOWLEDGE_TIMEOUT {
                return Ok(BtpSendData::Wait {
                    duration: ACKNOWLEDGE_TIMEOUT - time_since_last_sent,
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

pub mod uuids {

    use uuid::Uuid;
    pub struct Services;
    pub struct Characteristics;

    impl Services {
        pub const MATTER: Uuid = Uuid::from_u128(0x0000FFF6_0000_1000_8000_00805F9B34FB);
    }

    impl Characteristics {
        pub const WRITE: Uuid = Uuid::from_u128(0x18EE2EF5_263D_4559_959F_4F9C429F9D11);
        pub const READ: Uuid = Uuid::from_u128(0x18EE2EF5_263D_4559_959F_4F9C429F9D12);
        pub const COMMISSIONING_DATA: Uuid =
            Uuid::from_u128(0x64630238_8772_45F2_B87D_748A83218F04);
    }
}

bitflags! {
    struct BtpFlags: u8 {
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

// a nibble really
const BTP_PROTOCOL_VERSION: u8 = 0x04;
const MANAGEMENT_OPCODE: u8 = 0x6C;

pub trait BtpBuffer {
    fn buffer(&self) -> &[u8];
}

/// Abstract BTP message size, providing some helpful methods
/// over a buffer array.
#[derive(Clone, Debug, Default)]
struct BtpMessageBuffer {
    data: Vec<u8>,
    data_len: usize,
}

impl BtpMessageBuffer {
    pub fn set_u8(&mut self, index: usize, value: u8) {
        if self.data.len() < index + 1 {
            self.data.resize(index + 1, 0);
        }

        if self.data_len < index + 1 {
            self.data_len = index + 1;
        }
        self.data[index] = value;
    }

    pub fn set_u16(&mut self, index: usize, value: u16) {
        let h = ((value >> 8) & 0xFF) as u8;
        let l = (value & 0xFF) as u8;

        self.set_u8(index + 1, h);
        self.set_u8(index, l);
    }
}

impl BtpBuffer for BtpMessageBuffer {
    fn buffer(&self) -> &[u8] {
        self.data.split_at(self.data_len).0
    }
}

// Represents a handshake request
#[derive(Clone, Debug)]
struct BtpHandshakeRequest {
    buffer: BtpMessageBuffer,
}

impl Default for BtpHandshakeRequest {
    fn default() -> Self {
        let mut request = Self {
            buffer: Default::default(),
        };

        request.buffer.set_u8(0, BtpFlags::HANDSHAKE_REQUEST.bits);
        request.buffer.set_u8(1, MANAGEMENT_OPCODE);

        // Only one protocol supported, so no array of versions here, just one
        // Note that the LOW NIBBLE is the important one
        request.buffer.set_u8(2, BTP_PROTOCOL_VERSION);

        // sets the client window size to 0, to force internal buffer resizing
        request.buffer.set_u8(8, 0);

        request
    }
}

impl BtpHandshakeRequest {
    pub fn set_segment_size(&mut self, size: u16) {
        self.buffer.set_u16(6, size);
    }

    pub fn set_window_size(&mut self, size: u8) {
        self.buffer.set_u8(8, size);
    }
}

impl BtpBuffer for BtpHandshakeRequest {
    fn buffer(&self) -> &[u8] {
        self.buffer.buffer()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
struct BtpHandshakeResponse {
    selected_segment_size: u16,
    selected_window_size: u8,
}

impl BtpHandshakeResponse {
    fn parse(buffer: &[u8]) -> Result<BtpHandshakeResponse> {
        match buffer {
            [flags, opcode, protocol, segment_l, segment_h, window_size] => {
                if *flags != BtpFlags::HANDSHAKE_RESPONSE.bits {
                    return Err(anyhow!("Invalid response flags: 0x{:X}", flags));
                }

                if *opcode != MANAGEMENT_OPCODE {
                    return Err(anyhow!("Invalid management opcode: 0x{:X}", opcode));
                }

                // technically we should only look at low bits, but then reserved should be 0 anyway
                if *protocol != BTP_PROTOCOL_VERSION {
                    return Err(anyhow!("Invalid protocol: 0x{:X}", protocol));
                }

                Ok(BtpHandshakeResponse {
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

#[async_trait]
pub trait AsyncConnection {
    async fn write(&self, data: &[u8]) -> Result<()>;
    async fn read(&mut self) -> Result<Vec<u8>>;
}

pub struct BlePeripheralConnection<P: Peripheral> {
    peripheral: P,
    write_characteristic: Characteristic,
    read_characteristic: Characteristic,

    // NOTE: usage of Mutex because async_trait marks returns as Send
    //       The Pin below is also send because btleplug uses async_trait itself
    notifications: Mutex<Pin<Box<dyn Stream<Item = ValueNotification> + Send>>>,
}

impl<P: Peripheral> BlePeripheralConnection<P> {
    pub async fn new(peripheral: P) -> Result<BlePeripheralConnection<P>> {
        if !peripheral.is_connected().await? {
            info!("NOT connected. Conneting now...");
            peripheral.connect().await?;
        }

        info!("Device connected. CHIPoBLE can start.");
        info!("Discovering services...");
        peripheral.discover_services().await?;
        info!("Services found");

        let mut write_characteristic = None;
        let mut read_characteristic = None;

        for service in peripheral.services() {
            if service.uuid != uuids::Services::MATTER {
                continue;
            }

            info!("Matter service found: {:?}", service);

            for characteristic in service.characteristics {
                info!("   Characteristic: {:?}", characteristic);
                match characteristic.uuid {
                    uuids::Characteristics::READ => {
                        info!("      !! detected READ characteristic.");
                        read_characteristic = Some(characteristic);
                    }
                    uuids::Characteristics::WRITE => {
                        info!("      !! detected WRITE characteristic.");
                        write_characteristic = Some(characteristic);
                    }
                    uuids::Characteristics::COMMISSIONING_DATA => {
                        info!("      !! detected Commission data characteristic.");
                    }
                    _ => {
                        debug!("Unknown/unused characteristic: {:?}", characteristic);
                    }
                }
            }
        }

        match (read_characteristic, write_characteristic) {
            (None, None) => Err(anyhow!(
                "Device {:?} has no CHIPoBLE read or write CHIPoBLE characteristics",
                peripheral.id()
            )),
            (None, _) => Err(anyhow!(
                "Device {:?} has no CHIPoBLE read CHIPoBLE characteristics",
                peripheral.id()
            )),
            (_, None) => Err(anyhow!(
                "Device {:?} has no CHIPoBLE write CHIPoBLE characteristics",
                peripheral.id()
            )),
            (Some(read_characteristic), Some(write_characteristic)) => {
                info!("Device {:?} supports read/write for CHIPoBLE", peripheral);

                let notifications = Mutex::new(peripheral.notifications().await?);

                Ok(Self {
                    peripheral,
                    write_characteristic,
                    read_characteristic,
                    notifications,
                })
            }
        }
    }

    pub async fn handshake(&mut self) -> Result<()> {
        let mut request = BtpHandshakeRequest::default();
        request.set_segment_size(247); // no idea. Could be something else
        request.set_window_size(6); // no idea either

        self.raw_write(request).await?;

        info!("Subscribing to {:?} ...", self.read_characteristic);
        self.peripheral.subscribe(&self.read_characteristic).await?;

        println!("Reading ...");

        let response = BtpHandshakeResponse::parse(self.read().await?.as_slice())?;

        println!("Handshake response: {:?}", response);

        Ok(())
    }

    async fn raw_write<B: BtpBuffer>(&self, buffer: B) -> Result<()> {
        println!(
            "Writing to {:?}: {:?}",
            self.write_characteristic,
            buffer.buffer()
        );
        self.peripheral
            .write(
                &self.write_characteristic,
                buffer.buffer(),
                WriteType::WithResponse,
            )
            .await?;

        Ok(())
    }
}

#[async_trait]
impl<P: Peripheral> AsyncConnection for BlePeripheralConnection<P> {
    async fn write(&self, _data: &[u8]) -> Result<()> {
        // TODO items:
        //   - figure out framing
        //   - setup send and receive acks.
        //
        // General spec tips:
        //   - first buffer is the "Begin" frame
        //   - last buffer is the "End" frame
        //
        //   - there seems to be a limit on number of in flight packets (is there?
        //     I expect window sizese to be considered here. Need to read spec more.)
        //   - need to respect sizes received inside handshake.
        todo!();
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        // TODO: Reads should be able to unpack data
        //       likely want 'raw read' (no unpacking)
        //       and let this impl actually be used for general packets.
        loop {
            let value = {
                let mut guard = self.notifications.lock().await;
                guard.next().await
            };
            match value {
                None => return Err(anyhow!("No more data")),
                Some(ValueNotification {
                    uuid: uuids::Characteristics::READ,
                    value,
                }) => return Ok(value),
                Some(other_value) => {
                    warn!("Unexpected notification: {:?}", other_value);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use mock_instant::MockClock;

    use crate::{BtpSendData, BtpWindowState, PacketData, PacketSequenceInfo, ACKNOWLEDGE_TIMEOUT};

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
            ACKNOWLEDGE_TIMEOUT,
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
            ACKNOWLEDGE_TIMEOUT,
        );
        pipe.expect_wait_send(
            SendDirection::ClientToServer,
            PacketData::None,
            ACKNOWLEDGE_TIMEOUT,
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
            ACKNOWLEDGE_TIMEOUT,
        );
        MockClock::advance(Duration::from_secs(1));

        pipe.expect_wait_send(
            SendDirection::ServerToClient,
            PacketData::None,
            ACKNOWLEDGE_TIMEOUT - Duration::from_secs(1),
        );
        MockClock::advance(ACKNOWLEDGE_TIMEOUT - Duration::from_secs(1));

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
            ACKNOWLEDGE_TIMEOUT,
        );
    }
}
