#![feature(async_closure)]

use derive_builder::Builder;
use std::cell::RefCell;
use std::pin::Pin;
use uuids::characteristics;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use btleplug::api::Characteristic;
use btleplug::api::{Peripheral, ValueNotification, WriteType};

use framing::BtpWindowState;
use futures::{Stream, StreamExt};
use log::{debug, info, warn};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
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
    notifications: Mutex<Option<Pin<Box<dyn Stream<Item = ValueNotification> + Send>>>>,
}

impl<P: Peripheral> CharacteristicReader<P> {
    pub fn new(peripheral: P, characteristic: Characteristic) -> Self {
        Self {
            peripheral,
            characteristic,
            notifications: Mutex::new(None),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let mut guard = self.notifications.lock().await;

        if guard.is_some() {
            return Err(anyhow!("reader is already started"));
        }

        guard.replace(self.peripheral.notifications().await?);

        info!("Subscribing to {:?} ...", self.characteristic);
        self.peripheral.subscribe(&self.characteristic).await?;

        Ok(())
    }

    pub async fn raw_read(&mut self) -> Result<Vec<u8>> {
        loop {
            let value = {
                let mut guard = self.notifications.lock().await;
                match guard.as_mut() {
                    None => return Err(anyhow!("Reading not yet started")),
                    Some(stream) => stream.next().await,
                }
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

pub struct BlePeripheralConnection<P: Peripheral> {
    writer: CharacteristicWriter<P>,
    reader: Option<CharacteristicReader<P>>,

    // A queue of data to be sent over the wire?
    send_queue_tx: Mutex<RefCell<Option<UnboundedSender<Vec<u8>>>>>,
    receive_queue_rx: Mutex<RefCell<Option<UnboundedReceiver<Vec<u8>>>>>,
}

#[derive(Builder)]
#[builder(pattern = "owned")]
struct BtpProcessor {
    /// Items received for sending. are NOT yet framed
    send_rx: UnboundedReceiver<Vec<u8>>,

    /// Where to send received data
    recv_tx: UnboundedSender<Vec<u8>>,

    //reader: CharacteristicReader<P>,
    //writer: CharacteristicWriter<P>,

    btp: BtpWindowState,
}

impl BtpProcessor {
    pub async fn processing_loop(&mut self) {
        // ITEMS to use:
        //    - Need a BTP window state to control send/receive buffer states
        //    - separate framing logic. MUST frame correctly
        //    - have separate rx/tx ?
        //   - any wake up/sleep methods here
        //
        // - general state: determine when the next wakeup call is
        // -

        loop {
            tokio::select! {
                to_send = self.send_rx.recv() => {
                    println!("SEND TX DATA: {:?}", to_send);
                }
            }
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
                    send_queue_tx: Mutex::new(RefCell::new(None)),
                    receive_queue_rx: Mutex::new(RefCell::new(None)),
                })
            }
        }
    }

    async fn start_send_receive_loops(&mut self) -> Result<()> {
        let (send_tx, send_rx) = unbounded_channel();
        self.send_queue_tx
            .lock()
            .await
            .borrow_mut()
            .replace(send_tx);

        let (recv_tx, recv_rx) = unbounded_channel();
        self.receive_queue_rx
            .lock()
            .await
            .borrow_mut()
            .replace(recv_rx);

        let mut processor = BtpProcessorBuilder::default()
            .send_rx(send_rx)
            .recv_tx(recv_tx)
            //.reader(self.reader.take().unwrap())
            //.writer(self.writer.clone())
            .build()?;
        

        tokio::spawn(futures::future::lazy(async move |_| {
            processor.processing_loop().await
        }));

        Ok(())
    }

    pub async fn handshake(&mut self) -> Result<BtpHandshakeResponse> {
        let mut request = BtpHandshakeRequest::default();
        request.set_segment_size(247); // no idea. Could be something else
        request.set_window_size(6); // no idea either

        self.writer.raw_write(request).await?;

        // Subscription must be done only after the request raw write
        let reader = self.reader.as_mut().ok_or(anyhow!(
            "Reader not available (alredy cleared by another handshake?"
        ))?;
        reader.start().await?;

        let response = BtpHandshakeResponse::parse(reader.raw_read().await?.as_slice())?;

        self.start_send_receive_loops().await?;
        // TODO: spawn send/receive thread

        Ok(response)
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
        todo!();
    }
}
