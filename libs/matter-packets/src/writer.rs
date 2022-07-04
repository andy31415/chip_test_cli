use byteorder::{ByteOrder, LittleEndian};
use std::{error::Error, fmt::Display};

/// Errors when reading endian-specific data
#[derive(Debug, PartialEq)]
pub enum EndianWriteError {
    InsufficientSpace { missing: usize },
}

impl Display for EndianWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndianWriteError::InsufficientSpace { missing } => f.write_fmt(format_args!(
                "Insufficient space to write: need room for {} bytes",
                missing
            )),
        }
    }
}

impl Error for EndianWriteError {}

/// Allows writing of bytes into some destination.
/// Contains specific implementation for little-endian data processing
pub trait LittleEndianWriter {
    fn write(&mut self, data: &[u8]) -> core::result::Result<(), EndianWriteError>;

    fn write_le_u8(&mut self, data: u8) -> core::result::Result<(), EndianWriteError> {
        self.write(&[data])
    }

    fn write_le_u16(&mut self, data: u16) -> core::result::Result<(), EndianWriteError> {
        let mut buff = [0; 2];
        LittleEndian::write_u16(&mut buff, data);
        self.write(buff.as_slice())
    }

    fn write_le_u32(&mut self, data: u32) -> core::result::Result<(), EndianWriteError> {
        let mut buff = [0; 4];
        LittleEndian::write_u32(&mut buff, data);
        self.write(buff.as_slice())
    }
    fn write_le_u64(&mut self, data: u64) -> core::result::Result<(), EndianWriteError> {
        let mut buff = [0; 8];
        LittleEndian::write_u64(&mut buff, data);
        self.write(buff.as_slice())
    }
}

#[derive(Debug)]
pub struct SliceLittleEndianWriter<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> SliceLittleEndianWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    pub fn written(&self) -> usize {
        self.offset
    }
}

impl<'a> LittleEndianWriter for SliceLittleEndianWriter<'a> {
    fn write(&mut self, data: &[u8]) -> core::result::Result<(), EndianWriteError> {
        if data.len() + self.offset > self.buffer.len() {
            return Err(EndianWriteError::InsufficientSpace {
                missing: data.len() + self.offset - self.buffer.len(),
            });
        }

        self.buffer[self.offset..(self.offset + data.len())].copy_from_slice(data);
        self.offset += data.len();
        Ok(())
    }
}

/// Implements a [LittleEndianWriter] by keeping track of
/// how much data would be written if it would be serialized.
///
/// Discards any data written to self.
///
/// # Example
///
/// ```
/// use matter_packets::writer::{SpaceEstimator, LittleEndianWriter};
///
/// let mut estimator = SpaceEstimator::default();
///
/// assert_eq!(estimator.written(), 0);
///
/// estimator.write_le_u32(123);
/// assert_eq!(estimator.written(), 4);
///
/// estimator.write_le_u64(0xabcd);
/// assert_eq!(estimator.written(), 12);
///
/// estimator.write([0;28].as_slice());
/// assert_eq!(estimator.written(), 40);
/// ```
#[derive(Default, Debug)]
pub struct SpaceEstimator {
    offset: usize,
}

impl SpaceEstimator {
    pub fn written(&self) -> usize {
        self.offset
    }
}

impl LittleEndianWriter for SpaceEstimator {
    fn write(&mut self, data: &[u8]) -> core::result::Result<(), EndianWriteError> {
        self.offset += data.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_writer() {
        let mut buffer = [0u8; 16];
        {
            let mut writer = SliceLittleEndianWriter::new(buffer.as_mut_slice());

            assert!(writer.write_le_u32(0x12345678).is_ok());
            assert_eq!(writer.written(), 4);
            assert!(writer.write_le_u16(0xaabb).is_ok());
            assert_eq!(writer.written(), 6);
            assert!(writer.write_le_u64(0x1122334455667788).is_ok());
            assert_eq!(writer.written(), 14);
            assert!(writer.write_le_u8(0xff).is_ok());
            assert_eq!(writer.written(), 15);
        }

        assert_eq!(
            buffer[0..15],
            [
                0x78, 0x56, 0x34, 0x12, 0xbb, 0xaa, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                0xff
            ]
        );
    }

    #[test]
    fn slice_writer_overflow() {
        let mut buffer = [0u8; 3];
        let mut writer = SliceLittleEndianWriter::new(buffer.as_mut_slice());
        assert_eq!(
            writer.write_le_u32(123),
            Err(EndianWriteError::InsufficientSpace { missing: 1 })
        );
        assert_eq!(
            writer.write_le_u64(1122),
            Err(EndianWriteError::InsufficientSpace { missing: 5 })
        );
    }
}
