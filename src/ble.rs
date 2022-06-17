use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
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

#[async_trait]
pub trait AsyncConnection {
    async fn write(&self, data: &[u8], write_type: WriteType) -> Result<()>;
    async fn read(&mut self) -> Result<Vec<u8>>;
}

pub struct BlePeripheralConnection<P: Peripheral> {
    peripheral: P,
    write_characteristic: Characteristic,
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

                peripheral.subscribe(&read_characteristic).await?;

                Ok(Self {
                    peripheral,
                    write_characteristic,
                })
            }
        }
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

    async fn read(&mut self) -> Result<Vec<u8>> {
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
