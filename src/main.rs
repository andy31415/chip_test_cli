use ast::Command;
use bitflags::bitflags;
use std::fmt::Debug;
use std::time::Duration;

use anyhow::{anyhow, Result};
use btleplug::api::bleuuid::uuid_from_u16;
use byteorder::{ByteOrder, LittleEndian};
use log::{info, warn};

use btleplug::api::{Central, Manager as _, Peripheral, ScanFilter};
use btleplug::platform::{Adapter, Manager};
use dialoguer::{theme::ColorfulTheme, Completion, Input};
use tokio::time;

use lalrpop_util::lalrpop_mod;

lalrpop_mod!(pub cli);
mod ast;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
struct VendorId(u16);

#[derive(Clone, Copy, PartialEq, PartialOrd)]
struct ProductId(u16);

const MATTER_UUID: uuid::Uuid = uuid_from_u16(0xFFF6);

impl Debug for ProductId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("ProductId(0x{:X})", self.0))
    }
}

impl Debug for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("VendorId(0x{:X})", self.0))
    }
}

bitflags! {
    struct CommissionableDataFlags: u8 {
        const ADDITIONAL_DATA = 0x01;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
struct Discriminator(u16); // 12 bit max

#[derive(Debug, Clone, Copy, PartialEq)]
struct MatterBleCommissionableData {
    discriminator: Discriminator,
    vendor_id: Option<VendorId>,
    product_id: Option<ProductId>,
    flags: CommissionableDataFlags,
}

fn parse_advertising_data(data: &[u8]) -> Result<MatterBleCommissionableData> {
    if data.len() < 8 {
        return Err(anyhow!("Advertising data too short"));
    }
    // Advertising format:
    //   - 1 byte:    matter op-code. 0x00 is 'Commissionable', the rest are undefined
    //   - 2 byte LE: 4 bits version (0 is supported), 12 bits discriminator
    //   - 2 byte LE: vendor id. 0 means undefined/missing
    //   - 2 byte LE: product id. 0 means undefined/missing
    //   - 1 byte:    flags. bit0 is 'additional data' flag, rest are reserved and MUST be 0
    let opcode = data[0];

    if opcode != 0x00 {
        return Err(anyhow!(
            "Unsupported opcode. Only Commissionable (0x00) is supported."
        ));
    }

    let version_and_discriminator = LittleEndian::read_u16(&data[1..3]);
    let vendor_id = LittleEndian::read_u16(&data[3..5]);
    let product_id = LittleEndian::read_u16(&data[5..7]);
    let flags = data[7];

    let version = (version_and_discriminator >> 12) & 0x0F;

    if version != 0 {
        return Err(anyhow!(
            "Unsupported commissionable payload version: {}",
            version
        ));
    }

    let discriminator = Discriminator(version_and_discriminator & 0x0FFF);
    let vendor_id = if vendor_id == 0 {
        None
    } else {
        Some(VendorId(vendor_id))
    };
    let product_id = if product_id == 0 {
        None
    } else {
        Some(ProductId(product_id))
    };

    let flags = CommissionableDataFlags::from_bits(flags)
        .ok_or_else(|| anyhow!("Unable to parse flags {:x}", flags))?;

    Ok(MatterBleCommissionableData {
        discriminator,
        vendor_id,
        product_id,
        flags,
    })
}

struct Commands {
    commands: Vec<String>,
}
impl Default for Commands {
    fn default() -> Self {
        Self {
            commands: Command::all_strings(),
        }
    }
}

impl Completion for Commands {
    fn get(&self, input: &str) -> Option<String> {
        let matches = self
            .commands
            .iter()
            .filter(|option| option.starts_with(input))
            .collect::<Vec<_>>();

        if matches.len() == 1 {
            Some(matches[0].to_string())
        } else {
            None
        }
    }
}

fn help() {
    println!("Available commands: {}", Command::all_strings().join(", "));
    println!("Some specific syntaxes: ");
    println!("   scan <number_of_seconds> ");
}

async fn scan(adapter: &Adapter, duration: Duration) -> Result<()> {
    let scan_filter = ScanFilter::default();

    println!("Starting scan ... ");
    adapter
        .start_scan(scan_filter)
        .await
        .expect("Can't scan BLE adapter for connected devices.");

    time::sleep(duration).await;
    adapter.stop_scan().await?;

    println!("Starting done");

    Ok(())
}

async fn test(adapter: &Adapter) -> Result<()> {
    // FIXME: implement
    println!("NOT YET IMPLEMENTED!");
    Ok(())
}

async fn list(adapter: &Adapter) -> Result<()> {
    let peripherals = adapter.peripherals().await?;

    println!("Found {} peripherals", peripherals.len());

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

        let data = match props.service_data.get(&MATTER_UUID) {
            None => {
                warn!("{:?} Does not look like a matter device.", props.address);
                continue;
            }
            Some(data) => {
                let data = parse_advertising_data(data.as_slice());

                if data.is_err() {
                    eprintln!("Invalid matter data: {}", data.err().unwrap());
                    continue;
                }

                data.unwrap()
            }
        };

        if !props.service_data.contains_key(&MATTER_UUID) {}

        println!("Peripheral {:?}: {:?}", props.address, data);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let manager = Manager::new().await?;
    let adapter_list = manager.adapters().await?;

    if adapter_list.is_empty() {
        eprintln!("NO BLE adapters found!");
        return Err(anyhow::anyhow!("NO ADAPTERS!"));
    }

    let adapter = adapter_list.first().unwrap();

    info!("MATTER UUID: {:?}", MATTER_UUID);

    loop {
        let completion = Commands::default();
        let command = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Input (quit with 'exit') ")
            .completion_with(&completion)
            .interact_text()?;

        info!("User input: {:?}", command);
        let command = cli::CommandParser::new().parse(&command);
        info!("Parsed: {:?}", command);

        let result = match command {
            Ok(Command::List) => list(adapter).await,
            Ok(Command::Scan(duration)) => scan(adapter, duration).await,
            Ok(Command::Help) => {
                help();
                Ok(())
            },
            Ok(Command::Exit) => break,
            Ok(Command::Test) => test(adapter).await,
            Err(e) => Err(anyhow!("Command parse failed: {:?}", e)),
        };

        if result.is_err() {
            println!("ERR: {:?}", result);
            println!();
            help();
        }
    }

    Ok(())
}
