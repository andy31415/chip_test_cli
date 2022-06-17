use std::pin::Pin;

use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use bitflags::bitflags;
use btleplug::api::Characteristic;
use btleplug::api::Peripheral;
use btleplug::api::ValueNotification;
use btleplug::api::WriteType;
use futures::Stream;
use futures::StreamExt;
use log::debug;
use log::info;
use log::warn;
use tokio::sync::Mutex;

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
    notifications: Mutex<Pin<Box<dyn Stream<Item = ValueNotification> + Send>>>,
}

// TODO: this seems required for async trait implementation
//
// It seems 'notifications' is not sync but it should be.
// Need to figure it out
//unsafe impl<P:Peripheral> Sync for BlePeripheralConnection<P>{}

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
                                    //
        self.raw_write(request).await?;

        // TODO: subscribe after handshake?
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
