#![feature(async_closure)]

use std::collections::VecDeque;

use derive_builder::Builder;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use btleplug::api::Characteristic;
use btleplug::api::{Peripheral, WriteType};

use framing::{BtpSendData, BtpWindowState, PacketSequenceInfo};
use log::{debug, info};
use tokio_stream::StreamExt;

pub mod advertising_data;
pub mod framing;
pub mod handshake;
pub mod uuids;

use crate::framing::{BtpBuffer, BtpDataPacket, HeaderFlags};
use crate::handshake::{Request as BtpHandshakeRequest, Response as BtpHandshakeResponse};

#[async_trait]
pub trait AsyncConnection {
    async fn write(&mut self, data: &[u8]) -> Result<()>;
    async fn read(&mut self) -> Result<Vec<u8>>;
}

/// Wraps around a characteristic to send individual frames towards the device.
#[derive(Clone, Debug)]
struct CharacteristicWriter<P: Peripheral> {
    peripheral: P,
    characteristic: Characteristic,
}

impl<P: Peripheral> CharacteristicWriter<P> {
    pub fn new(peripheral: P, characteristic: Characteristic) -> Self {
        Self {
            peripheral,
            characteristic,
        }
    }

    pub async fn raw_write<B: BtpBuffer>(&self, buffer: B) -> Result<()> {
        println!(
            "Writing to {:?}: {:?}",
            self.characteristic,
            buffer.buffer()
        );
        self.peripheral
            .write(
                &self.characteristic,
                buffer.buffer(),
                WriteType::WithResponse,
            )
            .await?;

        Ok(())
    }
}

struct CharacteristicReader<P: Peripheral> {
    peripheral: P,
    characteristic: Characteristic,
}

impl<P: Peripheral> CharacteristicReader<P> {
    pub fn new(peripheral: P, characteristic: Characteristic) -> Self {
        Self {
            peripheral,
            characteristic,
        }
    }

    pub async fn start(self) -> Result<impl tokio_stream::Stream<Item = Vec<u8>>> {
        info!("Subscribing to {:?} ...", self.characteristic);

        let notif = self.peripheral.notifications().await?;

        // NOTE: it is important to aquire the notification stream BEFORE we subscribe, so
        //       that packets are not lost in transit.
        self.peripheral.subscribe(&self.characteristic).await?;

        Ok(notif.filter_map(|n| match n.uuid {
            uuids::characteristics::READ => Some(n.value),
            _ => None,
        }))
    }
}

pub struct BlePeripheralConnection<P: Peripheral> {
    writer: CharacteristicWriter<P>,
    reader: Option<CharacteristicReader<P>>,
}

/// Represents a pending message for sending
pub struct PendingData {
    payload: Vec<u8>,
    offset: usize, // offset into data. 0 if never sent
}

impl PendingData {
    pub fn new(payload: Vec<u8>) -> PendingData {
        PendingData { payload, offset: 0 }
    }

    /// Is the whole data done sending
    pub fn done(&self) -> bool {
        self.offset >= self.payload.len()
    }

    pub fn first(&self) -> bool {
        self.offset == 0
    }

    pub fn len_u16(&self) -> u16 {
        self.payload.len() as u16
    }

    /// Returns the next buffer given the provided maximum size of the buffer.
    /// Effectively splits the buffer into chunks.
    ///
    /// Example:
    ///
    /// ```
    /// use matter_btp::PendingData;
    ///
    /// let mut data = PendingData::new(vec![1,2,3,4,5,6,7]);
    ///
    /// assert!(data.first());
    /// assert_eq!(data.next_buffer(2), &[1,2]);
    /// assert!(!data.done());
    ///
    /// assert!(!data.first());
    /// assert_eq!(data.next_buffer(3), &[3,4,5]);
    /// assert!(!data.done());
    ///
    /// assert!(!data.first());
    /// assert_eq!(data.next_buffer(3), &[6,7]);
    /// assert!(data.done());
    ///
    /// ```
    pub fn next_buffer(&mut self, max_size: u16) -> &[u8] {
        let start = self.offset;
        self.offset += core::cmp::min(max_size as usize, self.payload.len() - self.offset);
        &self.payload[start..self.offset]
    }
}

/// Represents an open BTP connection.
#[derive(Builder)]
#[builder(pattern = "owned")]
struct BtpCommunicator<P, InputPackets>
where
    P: Peripheral,
    InputPackets: tokio_stream::Stream<Item = Vec<u8>> + Send,
{
    writer: CharacteristicWriter<P>,
    received_packets: InputPackets,
    state: BtpWindowState,
    segment_size: u16,

    #[builder(default)]
    send_queue: VecDeque<PendingData>,
}

impl<P: Peripheral, I> BtpCommunicator<P, I>
where
    I: tokio_stream::Stream<Item = Vec<u8>> + Send + Unpin,
{
    async fn send_next(&mut self, sequence_info: PacketSequenceInfo) -> Result<()> {
        let mut packet = framing::ResizableMessageBuffer::default();

        let mut packet_flags = HeaderFlags::empty();

        // where packet data is appended
        let data_offset = match sequence_info.ack_number {
            Some(nr) => {
                packet_flags |= HeaderFlags::CONTAINS_ACK;
                packet.set_u8(1, nr);
                packet.set_u8(2, sequence_info.sequence_number);
                3
            }
            None => {
                // IDLE packet without any ack ... this is generally odd
                packet.set_u8(0, 0);
                packet.set_u8(1, sequence_info.sequence_number);
                2
            }
        };

        match self.send_queue.front_mut() {
            Some(pending_data) => {
                if pending_data.first() {
                    packet_flags |= HeaderFlags::SEGMENT_BEGIN;
                    packet.set_u16(data_offset, pending_data.len_u16());
                    packet.set_at(
                        data_offset + 2,
                        pending_data.next_buffer(self.segment_size - 2),
                    );
                } else {
                    packet.set_at(data_offset, pending_data.next_buffer(self.segment_size));
                }

                if pending_data.done() {
                    packet_flags |= HeaderFlags::SEGMENT_END;
                    self.send_queue.pop_front();
                }
            }
            None => {} // nothing to append/change to the buffer
        }

        packet.set_u8(0, packet_flags.bits());
        self.writer.raw_write(packet).await
    }

    /// Operate interal send/receive loops:
    ///   - handles keep-alive back and forth
    ///   - sends if sending queue is non-empty
    ///   - receives if any data is sent by the remote side
    async fn drive_io(&mut self) -> Result<()> {
        let data = if self.send_queue.is_empty() {
            framing::PacketData::None
        } else {
            framing::PacketData::HasData
        };
        let state = self.state.prepare_send(data)?;

        match state {
            BtpSendData::Wait { duration } => {
                debug!("Cannot do anything for {:?}", duration);
                // Either sleep for the given duration OR receive some packet data
                //
                let recv_timeout = tokio::time::sleep(duration);
                let next_packet = self.received_packets.next();

                tokio::select! {
                    _ = recv_timeout => {
                        debug!("Timeout receiving reached");
                    },
                    packet = next_packet => {
                        match packet {
                            None => return Err(anyhow!("Remote closed connection")),
                            Some(vec) => {
                                let packet = BtpDataPacket::parse(vec.as_slice())?;
                                debug!("Packet data received: {:?}", packet);
                                self.state.packet_received(packet.sequence_info)?;

                                // TODO: assemble any packets as "receiving data"
                            }
                        }
                    }
                };
            }
            BtpSendData::Send(sequence_info) => {
                self.send_next(sequence_info).await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<P: Peripheral, I> AsyncConnection for BtpCommunicator<P, I>
where
    I: tokio_stream::Stream<Item = Vec<u8>> + Send + Unpin,
{
    async fn write(&mut self, data: &[u8]) -> Result<()> {
        info!("Writing data: {:?}", data);
        self.send_queue.push_back(PendingData::new(data.into()));

        while !self.send_queue.is_empty() {
            self.drive_io().await?;
        }
        info!("Writing data complete");
        Ok(())
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        loop {
            self.drive_io().await?;
            // Need exit logic: when we have some data received
        }
    }
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
            if service.uuid != uuids::services::MATTER {
                continue;
            }

            info!("Matter service found: {:?}", service);

            for characteristic in service.characteristics {
                info!("   Characteristic: {:?}", characteristic);
                match characteristic.uuid {
                    uuids::characteristics::READ => {
                        info!("      !! detected READ characteristic.");
                        read_characteristic = Some(characteristic);
                    }
                    uuids::characteristics::WRITE => {
                        info!("      !! detected WRITE characteristic.");
                        write_characteristic = Some(characteristic);
                    }
                    uuids::characteristics::COMMISSIONING_DATA => {
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

                Ok(Self {
                    writer: CharacteristicWriter::new(peripheral.clone(), write_characteristic),
                    reader: Some(CharacteristicReader::new(
                        peripheral.clone(),
                        read_characteristic,
                    )),
                })
            }
        }
    }

    pub async fn handshake(mut self) -> Result<impl AsyncConnection> {
        let mut request = BtpHandshakeRequest::default();
        request.set_segment_size(247); // no idea. Could be something else
        request.set_window_size(6); // no idea either

        self.writer.raw_write(request).await?;

        // Subscription must be done only after the request raw write
        let reader = self
            .reader
            .take()
            .ok_or_else(|| anyhow!("Reader not available (alredy cleared by another handshake?"))?;

        let mut packets = reader.start().await?;

        let response = BtpHandshakeResponse::parse(
            packets
                .next()
                .await
                .ok_or_else(|| anyhow!("No handshake response"))?
                .as_slice(),
        )?;

        println!("Handshake response: {:?}", response);

        Ok(BtpCommunicatorBuilder::default()
            .state(BtpWindowState::client(response.selected_window_size))
            .received_packets(packets)
            .writer(self.writer.clone())
            .segment_size(response.selected_segment_size)
            .build()?)
    }
}
