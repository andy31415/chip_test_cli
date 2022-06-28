use std::pin::Pin;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use btleplug::api::Characteristic;
use btleplug::api::{Peripheral, ValueNotification, WriteType};

use futures::{Stream, StreamExt};
use log::{debug, info, warn};
use tokio::sync::Mutex;

pub mod advertising_data;
pub mod framing;
pub mod handshake;
pub mod uuids;

use crate::handshake::{
    BtpBuffer, Request as BtpHandshakeRequest, Response as BtpHandshakeResponse,
};

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

    pub async fn handshake(&mut self) -> Result<BtpHandshakeResponse> {
        let mut request = BtpHandshakeRequest::default();
        request.set_segment_size(247); // no idea. Could be something else
        request.set_window_size(6); // no idea either

        self.raw_write(request).await?;

        // Subscription must be done only after the request raw write
        info!("Subscribing to {:?} ...", self.read_characteristic);
        self.peripheral.subscribe(&self.read_characteristic).await?;

        Ok(BtpHandshakeResponse::parse(self.read().await?.as_slice())?)
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
                    uuid: uuids::characteristics::READ,
                    value,
                }) => return Ok(value),
                Some(other_value) => {
                    warn!("Unexpected notification: {:?}", other_value);
                }
            }
        }
    }
}
