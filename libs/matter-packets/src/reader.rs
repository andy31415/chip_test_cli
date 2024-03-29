use byteorder::ByteOrder;
use std::{error::Error, fmt::Display};

/// Errors when reading endian-specific data
#[derive(Debug, PartialEq)]
pub enum EndianReadError {
    InsufficientData,
}

impl Display for EndianReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndianReadError::InsufficientData => f.write_str("Insufficient data"),
        }
    }
}

impl Error for EndianReadError {}

/// Allows taking out a sequence of bytes from some source of data.
pub trait BytesSource {
    /// Read a sequence of bytes from the source.
    fn read(&mut self, count: usize) -> core::result::Result<&[u8], EndianReadError>;
}

impl BytesSource for &[u8] {
    fn read(&mut self, count: usize) -> core::result::Result<&[u8], EndianReadError> {
        self.take(..count).ok_or(EndianReadError::InsufficientData)
    }
}

impl BytesSource for &mut [u8] {
    fn read(&mut self, count: usize) -> core::result::Result<&[u8], EndianReadError> {
        match self.take_mut(..count) {
            Some(data) => Ok(data),
            None => Err(EndianReadError::InsufficientData),
        }
    }
}

pub trait LittleEndianReader {
    fn read_le_u8(&mut self) -> core::result::Result<u8, EndianReadError>;
    fn read_le_u16(&mut self) -> core::result::Result<u16, EndianReadError>;
    fn read_le_u32(&mut self) -> core::result::Result<u32, EndianReadError>;
    fn read_le_u64(&mut self) -> core::result::Result<u64, EndianReadError>;

    fn read(&mut self, count: usize) -> core::result::Result<&[u8], EndianReadError>;
    fn skip(&mut self, count: usize) -> core::result::Result<(), EndianReadError>;
}

impl<T: BytesSource> LittleEndianReader for T {
    fn read_le_u8(&mut self) -> core::result::Result<u8, EndianReadError> {
        Ok(self.read(1)?[0])
    }

    fn read_le_u16(&mut self) -> core::result::Result<u16, EndianReadError> {
        Ok(byteorder::LittleEndian::read_u16(self.read(2)?))
    }

    fn read_le_u32(&mut self) -> core::result::Result<u32, EndianReadError> {
        Ok(byteorder::LittleEndian::read_u32(self.read(4)?))
    }

    fn read_le_u64(&mut self) -> core::result::Result<u64, EndianReadError> {
        Ok(byteorder::LittleEndian::read_u64(self.read(8)?))
    }

    fn skip(&mut self, count: usize) -> core::result::Result<(), EndianReadError> {
        self.read(count)?;
        Ok(())
    }

    fn read(&mut self, count: usize) -> core::result::Result<&[u8], EndianReadError> {
        T::read(self, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_parse_data() {
        let mut data: &[u8] = &[
            1, 0x11, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        assert_eq!(data.read_le_u8(), Ok(1));
        assert_eq!(data.read_le_u16(), Ok(0x1211));
        assert_eq!(data.read_le_u64(), Ok(0x0807060504030201));
        assert!(data.read_le_u8().is_err());

        let mut data: &[u8] = &[
            1, 0x11, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        assert_eq!(data.read_le_u32(), Ok(0x01121101));
        assert_eq!(data, &[0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn mut_parse_data() {
        let mut data: &mut [u8] = &mut [0xaa; 16];
        data[0] = 2;
        assert_eq!(data.read_le_u8(), Ok(2));

        data[0] = 0x34;
        data[1] = 0x12;
        assert_eq!(data.read_le_u16(), Ok(0x1234));

        data[0] = 0x11;
        assert_eq!(data.read_le_u64(), Ok(0xaaaaaaaaaaaaaa11));

        assert_eq!(data, [0xaa; 5]);
    }

    #[test]
    fn skip_support() {
        let mut data: &[u8] = &[1, 2, 3, 4, 5, 6, 7];

        assert!(data.skip(2).is_ok());
        assert_eq!(data.read_le_u16(), Ok(0x0403));
        assert!(data.skip(1).is_ok());
        assert_eq!(data, &[6, 7]);
        assert!(data.skip(0).is_ok());
        assert_eq!(data, &[6, 7]);
    }

    #[test]
    fn read_support() {
        let mut data: &[u8] = &[1, 2, 3, 4, 5, 6, 7];

        assert_eq!(LittleEndianReader::read(&mut data, 3).unwrap(), &[1, 2, 3]);
        assert_eq!(LittleEndianReader::read(&mut data, 0).unwrap(), &[]);
        assert_eq!(LittleEndianReader::read(&mut data, 1).unwrap(), &[4]);
        assert_eq!(data, &[5, 6, 7]);
    }
}
