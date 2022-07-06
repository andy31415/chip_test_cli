use core::str::from_utf8;

use crate::Value;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ConversionError {
    InvalidType,
    ConversionFailed,
    InvalidUtf8,
}

/// Implement the try from trait for various integer types. This allows conversion
/// from all signed and unsigned integers (assuming conversion succeeds) into the
/// underlying integer values
macro_rules! int_convert {
    ($type:ident) => {
        impl<'a> TryFrom<Value<'a>> for $type {
            type Error = ConversionError;

            fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
                match value {
                    Value::Signed(n) => Ok(n
                        .try_into()
                        .map_err(|_| ConversionError::ConversionFailed)?),
                    Value::Unsigned(n) => Ok(n
                        .try_into()
                        .map_err(|_| ConversionError::ConversionFailed)?),
                    _ => Err(ConversionError::InvalidType),
                }
            }
        }
    };
}

int_convert!(u8);
int_convert!(u16);
int_convert!(u32);
int_convert!(u64);
int_convert!(i8);
int_convert!(i16);
int_convert!(i32);
int_convert!(i64);

impl<'a> TryFrom<Value<'a>> for bool {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(value) => Ok(value),
            _ => Err(ConversionError::InvalidType),
        }
    }
}

impl<'a> TryFrom<Value<'a>> for f32 {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        match value {
            Value::Float(value) => Ok(value),
            _ => Err(ConversionError::InvalidType),
        }
    }
}

impl<'a> TryFrom<Value<'a>> for f64 {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        match value {
            Value::Double(value) => Ok(value),
            _ => Err(ConversionError::InvalidType),
        }
    }
}

impl<'a> TryFrom<Value<'a>> for &'a [u8] {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(value) => Ok(value),
            Value::Utf8(value) => Ok(value),
            _ => Err(ConversionError::InvalidType),
        }
    }
}

impl<'a> TryFrom<Value<'a>> for &'a str {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        if !matches!(value, Value::Utf8(_)) {
            return Err(ConversionError::InvalidType);
        }

        Ok(from_utf8(value.try_into()?).map_err(|_| ConversionError::InvalidUtf8)?)
    }
}

#[cfg(feature = "std")]
extern crate alloc;

#[cfg(feature = "std")]
use alloc::string::String;

#[cfg(feature = "std")]
impl<'a> TryFrom<Value<'a>> for String {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        if !matches!(value, Value::Utf8(_)) {
            return Err(ConversionError::InvalidType);
        }

        let value: &str = value.try_into()?;
        Ok(String::from(value))
    }
}

#[cfg(feature = "std")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
impl<'a> TryFrom<Value<'a>> for Vec<u8> {
    type Error = ConversionError;

    fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(value) => Ok(value.into()),
            Value::Utf8(value) => Ok(value.into()),
            _ => Err(ConversionError::InvalidType),
        }
    }
}

macro_rules! try_from_for_option {
    ($type:ty) => {
        impl<'a> TryFrom<Value<'a>> for Option<$type> {
            type Error = ConversionError;

            fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
                if matches!(value, Value::Null) {
                    return Ok(None);
                }

                Ok(Some(value.try_into()?))
            }
        }
    };
}

try_from_for_option!(u8);
try_from_for_option!(u16);
try_from_for_option!(u32);
try_from_for_option!(u64);
try_from_for_option!(i8);
try_from_for_option!(i16);
try_from_for_option!(i32);
try_from_for_option!(i64);
try_from_for_option!(f32);
try_from_for_option!(f64);
try_from_for_option!(&'a [u8]);

#[cfg(feature = "std")]
try_from_for_option!(Vec<u8>);

#[cfg(feature = "std")]
try_from_for_option!(String);

#[cfg(test)]
mod tests {
    use crate::ContainerType;

    use super::*;

    #[test]
    fn integer_conversion() {
        assert_eq!(Value::Signed(1).try_into(), Ok(1u8));
        assert_eq!(Value::Signed(10).try_into(), Ok(10u8));
        assert_eq!(Value::Signed(1).try_into(), Ok(1u32));
        assert_eq!(Value::Signed(2).try_into(), Ok(2u64));

        assert_eq!(Value::Signed(-2).try_into(), Ok(-2i8));
        assert_eq!(Value::Signed(-3).try_into(), Ok(-3i16));
        assert_eq!(Value::Signed(-20).try_into(), Ok(-20i32));
        assert_eq!(Value::Signed(-40).try_into(), Ok(-40i64));

        assert_eq!(Value::Unsigned(1).try_into(), Ok(1u8));
        assert_eq!(Value::Unsigned(10).try_into(), Ok(10u8));
        assert_eq!(Value::Unsigned(1).try_into(), Ok(1u32));
        assert_eq!(Value::Unsigned(2).try_into(), Ok(2u64));

        assert_eq!(Value::Unsigned(1).try_into(), Ok(1i8));
        assert_eq!(Value::Unsigned(10).try_into(), Ok(10i8));
        assert_eq!(Value::Unsigned(1).try_into(), Ok(1i32));
        assert_eq!(Value::Unsigned(2).try_into(), Ok(2i64));

        // Validate that ranges are taken into account
        assert!(TryInto::<u8>::try_into(Value::Unsigned(0x1FF)).is_err());
        assert_eq!(TryInto::<u16>::try_into(Value::Unsigned(0x1FF)), Ok(0x1FF));

        assert!(TryInto::<u64>::try_into(Value::Signed(-1)).is_err());
        assert_eq!(TryInto::<i8>::try_into(Value::Signed(-1)), Ok(-1));

        // other types should fail
        assert!(TryInto::<u8>::try_into(Value::Bool(false)).is_err());
        assert!(TryInto::<u8>::try_into(Value::Float(0.)).is_err());
        assert!(TryInto::<u8>::try_into(Value::Null).is_err());
        assert!(TryInto::<u8>::try_into(Value::ContainerEnd).is_err());
        assert!(TryInto::<u8>::try_into(Value::ContainerStart(ContainerType::Structure)).is_err());

        assert_eq!(TryInto::<Option<u8>>::try_into(Value::Null), Ok(None));
        assert_eq!(TryInto::<Option<i32>>::try_into(Value::Null), Ok(None));
    }

    #[test]
    fn bytes_conversion() {
        assert_eq!(
            Value::Bytes(&[97, 98, 99]).try_into(),
            Ok([97, 98, 99].as_slice())
        );

        assert_eq!(
            Value::Utf8(&[97, 98, 99]).try_into(),
            Ok([97, 98, 99].as_slice())
        );

        assert_eq!(
            Value::Utf8(&[0xE2, 0x9D, 0xA4, 0x20, 0xF0, 0x9F, 0xA6, 0x80]).try_into(),
            Ok("❤ 🦀")
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn std_string_conversion() {
        assert_eq!(
            Value::Utf8(&[97, 98, 99]).try_into(),
            Ok(String::from("abc"))
        );

        assert_eq!(
            Value::Utf8(&[0xF0, 0x9F, 0xA6, 0x80]).try_into(),
            Ok(String::from("🦀"))
        );
    }

#[cfg(feature = "std")]
use alloc::vec;

    #[cfg(feature = "std")]
    #[test]
    fn vec_conversion() {
        assert_eq!(
            Value::Utf8(&[97, 98, 99]).try_into(),
            Ok(vec![97, 98, 99])
        );

        assert_eq!(
            Value::Utf8(&[0, 0xFF, 0x80, 0xFF, 0xFF]).try_into(),
            Ok(vec![0, 0xFF, 0x80, 0xFF, 0xFF])
        );

    }
}
