use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use bitflags::bitflags;
use btleplug::api::Characteristic;
use btleplug::api::Peripheral;
use btleplug::api::ValueNotification;
use btleplug::api::WriteType;
use futures::StreamExt;
use log::debug;
use log::info;
use log::warn;

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
    pub fn clear(&mut self) {
        self.data_len = 0;
    }

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

#[async_trait]
pub trait AsyncConnection {
    async fn write(&self, data: &[u8], write_type: WriteType) -> Result<()>;
    async fn read(&self) -> Result<Vec<u8>>;
}

pub struct BlePeripheralConnection<P: Peripheral> {
    peripheral: P,
    write_characteristic: Characteristic,
    read_characteristic: Characteristic,
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

                Ok(Self {
                    peripheral,
                    write_characteristic,
                    read_characteristic,
                })
            }
        }
    }

    pub async fn handshake(&self) -> Result<()> {
        let mut request = BtpHandshakeRequest::default();
        request.set_segment_size(23); // no idea. Could be something else
        request.set_window_size(244); // no idea either
                                      //
        self.raw_write(request).await?;
        
        // MUST subscribe after request sent
        info!("Subscribing to {:?} ...", self.read_characteristic);
        self.peripheral.subscribe(&self.read_characteristic).await?;

        // expected response:
        //  0b0110_0101 0x6C (Management OpCode)
        //  0x?V where V is the protocol version. Likely 0x04
        //  0x.. BTP segment size (one byte)
        //  window size (2 bytes)
        println!("Reading ...");

        let data = self.read().await?;

        println!("BLE DATA received: {:?}", data);

        // Handshake response
        //  - 0b01100101
        //  - Management OpCode = 0x6C
        //  - 0x?V - protocol version
        //  - 0xXXXX - 16-bit segment size
        //  - 0xXX - 8-bit window size

        Ok(())
    }

    async fn raw_write<B: BtpBuffer>(&self, buffer: B) -> Result<()> {
        println!("Writing to {:?}: {:?}", self.write_characteristic, buffer.buffer());
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
    async fn write(&self, data: &[u8], write_type: WriteType) -> Result<()> {
        self.peripheral
            .write(&self.write_characteristic, data, write_type)
            .await?;

        Ok(())
    }

    async fn read(&self) -> Result<Vec<u8>> {
        let mut notifications = self.peripheral.notifications().await?;
        loop {
            let value = notifications.next().await;
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
