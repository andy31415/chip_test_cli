use ast::Command;

use matter_btp::{AsyncConnection, BlePeripheralConnection};

use std::time::Duration;

use anyhow::{anyhow, Result};

use log::{info, warn};

use btleplug::api::{Central, Manager as _, Peripheral, ScanFilter};
use btleplug::platform::{Adapter, Manager, PeripheralId};
use dialoguer::{theme::ColorfulTheme, Completion, Input};
use tokio::time;

use lalrpop_util::lalrpop_mod;

lalrpop_mod!(
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::all))]
    pub cli
);
mod ast;

use matter_btp::advertising_data::Commissionable;

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
    println!("   test <list_device_index> ");
}

/// The execution shell, to be stateful
struct Shell<'a> {
    adapter: &'a Adapter,
    available_peripherals: Vec<PeripheralId>,
}

impl<'a> Shell<'a> {
    fn new(adapter: &'a Adapter) -> Self {
        Self {
            adapter,
            available_peripherals: Vec::default(),
        }
    }

    async fn list(&mut self) -> Result<()> {
        let peripherals = self.adapter.peripherals().await?;

        println!("Found {} peripherals", peripherals.len());

        self.available_peripherals.clear();
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

            let data = match props.service_data.get(&matter_btp::uuids::services::MATTER) {
                None => {
                    warn!("{:?} Does not look like a matter device.", props.address);
                    continue;
                }
                Some(data) => {
                    let data = Commissionable::parse(data.as_slice());

                    if data.is_err() {
                        eprintln!("Invalid matter data: {}", data.err().unwrap());
                        continue;
                    }

                    data.unwrap()
                }
            };

            if !props
                .service_data
                .contains_key(&matter_btp::uuids::services::MATTER)
            {}

            println!(
                "{} Peripheral {:?}:",
                self.available_peripherals.len(),
                peripheral.id()
            );
            println!("    {:?}", data);

            self.available_peripherals.push(peripheral.id());
        }
        Ok(())
    }

    async fn scan(&self, duration: Duration) -> Result<()> {
        let scan_filter = ScanFilter::default();

        println!("Starting scan ... ");
        self.adapter
            .start_scan(scan_filter)
            .await
            .expect("Can't scan BLE adapter for connected devices.");

        time::sleep(duration).await;
        self.adapter.stop_scan().await?;

        println!("Starting done");

        Ok(())
    }

    async fn test(&self, idx: usize) -> Result<()> {
        if idx >= self.available_peripherals.len() {
            return Err(anyhow!(
                "No device with index {}. Cached {} devices. Run 'list' to refresh/re-list.",
                idx,
                self.available_peripherals.len()
            ));
        }

        let peripheral = self
            .adapter
            .peripheral(&self.available_peripherals[idx])
            .await?;

        println!("Got peripheral: {:?}", peripheral.id());

        let mut conn = BlePeripheralConnection::new(peripheral)
            .await?
            .handshake()
            .await?;

        // TODO: actually need to send PASE
        let data = conn.read().await?;
        println!("DATA RECEIVED: {:?}", data);

        // TODO:
        //   - use connection for PASE
        //   - use connection for cluster operations
        //   - start implementing CHIP framing after that!
        //
        println!("Need more implementation here");

        Ok(())
    }
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

    let mut shell = Shell::new(adapter);

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
            Ok(Command::List) => shell.list().await,
            Ok(Command::Scan(duration)) => shell.scan(duration).await,
            Ok(Command::Help) => {
                help();
                Ok(())
            }
            Ok(Command::Exit) => break,
            Ok(Command::Test(idx)) => shell.test(idx as usize).await,
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
