use std::ffi;
use std::fmt;

use anyhow::Context as _;
use hex_literal::hex;

const VID_FIRMWARE: u16 = 0x1209;
const PID_FIRMWARE: u16 = 0xbeee;

const FIRMWARE_READER_NAME: &[u8] = b"SoloKeys Solo 2 [CCID/ICCD Interface]";

const AID_ADMIN: &[u8] = &hex!("A00000084700000001");
const AID_PROVISIONER: &[u8] = &hex!("A00000084701000001");

#[derive(Clone, Debug)]
enum Device {
    Bootloader {
        vid: u16,
        pid: u16,
        uuid: u128,
    },
    Firmware {
        bus: u8,
        address: u8,
    },
}

impl From<lpc55::bootloader::Bootloader> for Device {
    fn from(bootloader: lpc55::bootloader::Bootloader) -> Self {
        Self::Bootloader {
            vid: bootloader.vid,
            pid: bootloader.pid,
            uuid: bootloader.uuid,
        }
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bootloader { vid, pid, uuid } => write!(f, "Bootloader {:04x}:{:04x} with uuid {:032x}", vid, pid, uuid),
            Self::Firmware { bus, address } => write!(f, "Firmware on bus {:03} device {:03}", bus, address),
        }
    }
}

#[derive(Debug, Default)]
struct ReaderStatus {
    firmware_readers: Vec<FirmwareReader>,
    unsupported_readers: Vec<anyhow::Error>,
    other_readers: Vec<ffi::CString>,
}

#[derive(Debug)]
enum Reader {
    Firmware(FirmwareReader),
    Unsupported(anyhow::Error),
    Other(ffi::CString),
}

#[derive(Clone, Debug)]
struct FirmwareReader {
    uuid: u128,
    provisioner: bool,
}

impl fmt::Display for FirmwareReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uuid {:032x}", self.uuid)?;
        if self.provisioner {
            write!(f, " with provisioner firmware")?;
        }
        Ok(())
    }
}

fn find_bootloader_devices() -> Vec<Device> {
    lpc55::bootloader::Bootloader::list()
        .into_iter()
        .map(From::from)
        .collect()
}

fn find_firmware_devices() -> anyhow::Result<Vec<Device>> {
    let mut firmware_devices = Vec::new();
    let ctx = libusb::Context::new().context("Failed to establish libusb context")?;
    let devices = ctx.devices().context("Failed to list USB devices")?;
    for device in devices.iter() {
        let desc = device.device_descriptor().context("Failed to query device descriptor")?;
        if desc.vendor_id() == VID_FIRMWARE && desc.product_id() == PID_FIRMWARE {
            firmware_devices.push(Device::Firmware {
                bus: device.bus_number(),
                address: device.address(),
            });
        }
    }
    Ok(firmware_devices)
}

fn find_devices() -> anyhow::Result<Vec<Device>> {
    let mut devices = Vec::new();
    devices.extend(find_bootloader_devices());
    devices.extend(find_firmware_devices()?);
    Ok(devices)
}

fn get_reader_status() -> anyhow::Result<ReaderStatus> {
    let mut reader_status = ReaderStatus::default();
    for reader in get_readers()? {
        match reader {
            Reader::Firmware(reader) => reader_status.firmware_readers.push(reader),
            Reader::Unsupported(error) => reader_status.unsupported_readers.push(error),
            Reader::Other(reader) => reader_status.other_readers.push(reader),
        }
    }
    Ok(reader_status)
}

fn ccid_transmit(tx: &pcsc::Transaction<'_>, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> anyhow::Result<Vec<u8>> {
    use std::convert::TryFrom as _;

    let mut request = vec![
        // Class
        0x00,
        // Ins
        ins,
        // P1
        p1,
        // P2
        p2,
    ];

    if !data.is_empty() {
        // Lc
        request.push(u8::try_from(data.len()).context("AID too long")?);
        // Data
        request.extend_from_slice(data);
    }
    if let Some(le) = le {
        // Le
        request.push(le);
    }

    let response_len = le.map(|le| {
        match le {
            0 => usize::from(u8::MAX) + 1,
            _ => usize::from(le)
        }
    }).unwrap_or_default() + 2;
    let mut response = vec![0; response_len];

    let n = tx.transmit(&request, &mut response).context("Failed to transmit data to smartcard")?.len();
    response.truncate(n);

    let sw2 = response.pop().context("CCID response too short")?;
    let sw1 = response.pop().context("CCID response too short")?;
    if (sw1, sw2) == (0x90, 0x00) {
        Ok(response)
    } else {
        Err(anyhow::anyhow!("CCID command failed with status code {:X}{:X}", sw1, sw2))
    }
}

fn ccid_select(tx: &pcsc::Transaction<'_>, aid: &[u8]) -> anyhow::Result<()> {
    ccid_transmit(tx, 0xA4, 0x04, 0x00, aid, None)
        .map(|_| {})
        .with_context(|| format!("Failed to select AID {:x?}", aid))
}

fn ccid_select2(tx: &pcsc::Transaction<'_>, aid: &[u8]) -> anyhow::Result<()> {
    // Provisioner select returns 16 byte uuid
    ccid_transmit(tx, 0xA4, 0x04, 0x00, aid, Some(16))
        .map(|_| {})
        .with_context(|| format!("Failed to select AID {:x?}", aid))
}

fn admin_get_uuid(tx: &pcsc::Transaction<'_>) -> anyhow::Result<u128> {
    ccid_transmit(tx, 0x62, 0x00, 0x00, &[], Some(16))
        .context("Failed to query UUID")
        .and_then(|response| {
            use std::convert::TryInto as _;
            response
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected 16 UUID bytes"))
                .map(u128::from_be_bytes)
        })
}

fn get_firmware_reader(ctx: &pcsc::Context, reader: &ffi::CStr) -> anyhow::Result<FirmwareReader> {
    let mut reader = ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::T1)
        .context("Failed to connect to smartcard reader")?;
    let tx = reader.transaction().context("Failed to start smartcard transaction")?;
    ccid_select(&tx, AID_ADMIN).context("Failed to select admin application")?;
    let uuid = admin_get_uuid(&tx).context("Failed to query UUID")?;
    let provisioner = ccid_select2(&tx, AID_PROVISIONER).is_ok();
    Ok(FirmwareReader {
        uuid,
        provisioner,
    })
}

fn get_readers() -> anyhow::Result<Vec<Reader>> {
    let ctx = pcsc::Context::establish(pcsc::Scope::System).context("Failed to establish pcsc context")?;
    Ok(ctx.list_readers_owned()
        .context("Failed to list pcsc readers")?
        .into_iter()
        .map(|reader| {
            if reader.as_bytes().starts_with(FIRMWARE_READER_NAME) {
                match get_firmware_reader(&ctx, &reader) {
                    Ok(reader) => Reader::Firmware(reader),
                    Err(err) => Reader::Unsupported(err),
                }
            } else {
                Reader::Other(reader)
            }
        })
        .collect())
}

fn main() -> anyhow::Result<()> {
    let devices = find_devices()?;
    anyhow::ensure!(!devices.is_empty(), "No supported devices found");

    println!("{} device(s) found:", devices.len());
    for device in &devices {
        println!("- {}", device);
    }

    let reader_status = get_reader_status()?;

    if !reader_status.firmware_readers.is_empty() {
        println!("");
        println!("Firmware status:");
        for reader in &reader_status.firmware_readers {
            println!("- {}", reader);
        }
    }

    if !reader_status.unsupported_readers.is_empty() {
        println!("");
        println!("Firmware errors:");
        for error in &reader_status.unsupported_readers {
            println!("- {}", error);
        }
    }

    println!("");
    let firmware_device_count = devices.iter().filter(|device| matches!(device, Device::Firmware { bus: _, address: _ })).count();
    if firmware_device_count > reader_status.firmware_readers.len() {
        println!("Warning: Could not connect to one or more firmware devices.  Check that the updated Info.plist file is installed.");
    }
    if firmware_device_count > 1 {
        println!("Warning: Multiple firmware devices connected.  solo2 currently only supports accessing a single device.");
    }
    if !reader_status.other_readers.is_empty() {
        println!("Warning: Found unsupported smartcard readers.  Please disconnect these readers before using solo2: {:?}", reader_status.other_readers);
    }

    Ok(())
}
