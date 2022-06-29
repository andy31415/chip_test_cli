#![feature(async_closure)]

use derive_builder::Builder;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use btleplug::api::Characteristic;
use btleplug::api::{Peripheral, WriteType};

use framing::BtpWindowState;
use log::{debug, info};
use tokio_stream::StreamExt;

pub mod advertising_data;
pub mod framing;
pub mod handshake;
pub mod uuids;

use crate::handshake::{
    BtpBuffer, Request as BtpHandshakeRequest, Response as BtpHandshakeResponse,
};

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
        self.peripheral.subscribe(&self.characteristic).await?;

        let notif = self.peripheral.notifications().await?;

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
}

impl<P: Peripheral, I> BtpCommunicator<P, I>
where
    I: tokio_stream::Stream<Item = Vec<u8>> + Send,
{
    /// Operate interal send/receive loops:
    ///   - handles keep-alive back and forth
    ///   - sends if sending queue is non-empty
    ///   - receives if any data is sent by the remote side
    async fn drive_io(&mut self) {
        // - cases:
        //    - determine what to write (if anything)
        //    - ask state to perform read or write
        //    - select on either read or write
        //    - Need: i/o in a loop (reading loop? stream of values for read data?)

        // TODO: select reader and writer
        //  - for writing:
        //    - figure out if anything to send (state decides)
        //    - have some form of timeout

        todo!()
    }
}

#[async_trait]
impl<P: Peripheral, I> AsyncConnection for BtpCommunicator<P, I>
where
    I: tokio_stream::Stream<Item = Vec<u8>> + Send,
{
    async fn write(&mut self, data: &[u8]) -> Result<()> {
        todo!();
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        todo!();
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
        let reader = self.reader.take().ok_or(anyhow!(
            "Reader not available (alredy cleared by another handshake?"
        ))?;

        let mut packets = reader.start().await?;

        let response = BtpHandshakeResponse::parse(
            packets
                .next()
                .await
                .ok_or(anyhow!("No handshake response"))?
                .as_slice(),
        )?;

        println!("Handshake response: {:?}", response);

        // TODO: also use response.selected_segment_size

        Ok(BtpCommunicatorBuilder::default()
            .state(BtpWindowState::client(response.selected_window_size))
            .received_packets(packets)
            .writer(self.writer.clone())
            .build()?)
    }
}
