use std::time::Duration;

use anyhow::Result;
use btleplug::api::bleuuid::uuid_from_u16;
use log::{info, warn};

use btleplug::api::{Central, Manager as _, Peripheral, ScanFilter};
use btleplug::platform::Manager;
use tokio::time;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    info!("Hello, world!");

    let manager = Manager::new().await?;
    let adapter_list = manager.adapters().await?;

    if adapter_list.is_empty() {
        eprintln!("NO BLE adapters found!");
        return Err(anyhow::anyhow!("NO ADAPTERS!"));
    }

    let adapter = adapter_list.first().unwrap();

    let matter_uuid = uuid_from_u16(0xFFF6);
    info!("UUID: {:?}", matter_uuid);

    let scan_filter = ScanFilter::default();
    /*
    let scan_filter = ScanFilter{services: vec![matter_uuid] });
     */

    adapter
        .start_scan(scan_filter)
        .await
        .expect("Can't scan BLE adapter for connected devices.");

    time::sleep(Duration::from_secs(2)).await;
    let peripherals = adapter.peripherals().await?;

    info!("Found {} peripherals", peripherals.len());

    for peripheral in peripherals {
        let props = peripheral.properties().await;
        if let Err(err) = props {
            warn!("Cannot get properties of {:?}: {:?}", peripheral, err);
            continue;
        }
        let props = props.unwrap();

        if props.is_none() {
            warn!("  CANNOT get properties of peripheral");
            continue;
        }
        let props = props.unwrap();

        if !props.service_data.contains_key(&matter_uuid) {
            warn!("{:?} Does not look like a matter device.", props.address);
            continue;
        }

        info!("Peripheral {:?}: {:?}", props.address, props.service_data);
        /*
        if matches!(props.rssi, Some(level) if level < -60) {
            warn!("  RSSI too low.");
            continue;
        }
        */

        let connected = peripheral.is_connected().await?;
        if connected {
            info!("  CONNECTED");
        } else {
            info!("  NOT CONNECTED. Connecting now.");
            if let Err(err) = peripheral.connect().await {
                eprintln!("   Failed to connect: {:?}", err);
                continue;
            }
        }

        let props = peripheral.properties().await.unwrap().unwrap();
        info!("  Local name {:?}", props.local_name);

        peripheral.discover_services().await?;
        for service in peripheral.services() {
            info!("  SERVICE {:?}", service.uuid);
        }

        if connected {
            peripheral.disconnect().await.expect("Disconnecting");
        }
    }

    Ok(())
}
