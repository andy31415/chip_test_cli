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
macro_rules! try_from_value_to_number {
    ($type:ty) => {
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

try_from_value_to_number!(u8);
try_from_value_to_number!(u16);
try_from_value_to_number!(u32);
try_from_value_to_number!(u64);
try_from_value_to_number!(i8);
try_from_value_to_number!(i16);
try_from_value_to_number!(i32);
try_from_value_to_number!(i64);

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
            // f32 should not lose precision when converted to f64
            Value::Float(value) => Ok(value.into()),
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

/* Conversions from data into value */

macro_rules! from_type_to_value {
    ($type:ty, $actual:path) => {
        impl<'a> From<$type> for Value<'a> {
            fn from(value: $type) -> Self {
                $actual(value.into())
            }
        }
    };
}
from_type_to_value!(i8, Value::Signed);
from_type_to_value!(i16, Value::Signed);
from_type_to_value!(i32, Value::Signed);
from_type_to_value!(i64, Value::Signed);
from_type_to_value!(u8, Value::Unsigned);
from_type_to_value!(u16, Value::Unsigned);
from_type_to_value!(u32, Value::Unsigned);
from_type_to_value!(u64, Value::Unsigned);
from_type_to_value!(bool, Value::Bool);
from_type_to_value!(f32, Value::Float);
from_type_to_value!(f64, Value::Double);

/// Converts from strings into values.
///
/// ```
/// use tlv_stream::Value;
/// use tlv_stream::convert::*;
///
/// let value: Value = "😂".into();
/// assert_eq!(value, Value::Utf8(&[240, 159, 152, 130]));
/// ```
impl<'a> From<&'a str> for Value<'a> {
    fn from(value: &'a str) -> Self {
        Value::Utf8(value.as_bytes())
    }
}

/// Converts from bytes into values
///
/// ```
/// use tlv_stream::Value;
/// use tlv_stream::convert::*;
///
/// let value: Value = [1, 2, 3].as_slice().into();
/// assert_eq!(value, Value::Bytes(&[1, 2, 3]));
/// ```
impl<'a> From<&'a [u8]> for Value<'a> {
    fn from(value: &'a [u8]) -> Self {
        Value::Bytes(value)
    }
}

/// Converts from a string to a value:
///
/// ```
/// use tlv_stream::Value;
/// use tlv_stream::convert::*;
///
/// let data = String::from("ABC");
/// let value: Value = (&data).into();
/// assert_eq!(value, Value::Utf8(&[65, 66, 67]));
/// ```
#[cfg(feature = "std")]
impl<'a> From<&'a String> for Value<'a> {
    fn from(value: &'a String) -> Self {
        Value::Utf8(value.as_bytes())
    }
}

/// Converts from a vector to a value:
///
/// ```
/// use tlv_stream::Value;
/// use tlv_stream::convert::*;
///
/// let data = vec![1u8, 2u8, 3u8];
/// let value: Value = (&data).into();
/// assert_eq!(value, Value::Bytes(&[1, 2, 3]));
/// ```
#[cfg(feature = "std")]
impl<'a> From<&'a Vec<u8>> for Value<'a> {
    fn from(value: &'a Vec<u8>) -> Self {
        Value::Bytes(value.as_slice())
    }
}

macro_rules! from_option_into_value {
    ($type:ty) => {
        impl<'a> From<Option<$type>> for Value<'a> {
            fn from(value: Option<$type>) -> Self {
                match value {
                    None => Value::Null,
                    x => x.into(),
                }
            }
        }
    };
}

from_option_into_value!(i8);
from_option_into_value!(i16);
from_option_into_value!(i32);
from_option_into_value!(i64);
from_option_into_value!(u8);
from_option_into_value!(u16);
from_option_into_value!(u32);
from_option_into_value!(u64);
from_option_into_value!(f32);
from_option_into_value!(f64);
from_option_into_value!(&str);
from_option_into_value!(&[u8]);

#[cfg(feature = "std")]
from_option_into_value!(&String);

#[cfg(feature = "std")]
from_option_into_value!(&Vec<u8>);

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
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
    fn bool_conversion() {
        assert_eq!(Value::Bool(true).try_into(), Ok(true));
        assert_eq!(Value::Bool(false).try_into(), Ok(false));

        assert!(TryInto::<bool>::try_into(Value::Null).is_err());
        assert!(TryInto::<bool>::try_into(Value::Float(123.)).is_err());
        assert!(TryInto::<bool>::try_into(Value::Double(321.)).is_err());
    }

    #[test]
    fn float_conversion() {
        assert_eq!(Value::Float(1.25).try_into(), Ok(1.25f32));
        assert_eq!(Value::Double(4.5).try_into(), Ok(4.5));

        assert!(TryInto::<f32>::try_into(Value::Null).is_err());
        assert!(TryInto::<f64>::try_into(Value::ContainerStart(ContainerType::Array)).is_err());
        assert!(TryInto::<f64>::try_into(Value::Bool(false)).is_err());
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

    #[test]
    fn optional_support() {
        let value: Result<Option<u8>, ConversionError> = Value::Null.try_into();
        assert_eq!(value, Ok(None));

        let value: Result<Option<String>, ConversionError> = Value::Null.try_into();
        assert_eq!(value, Ok(None));

        let value: Result<Option<&[u8]>, ConversionError> = Value::Null.try_into();
        assert_eq!(value, Ok(None));

        let value: Option<u32> = None;
        let value: Value = value.into();
        assert_eq!(value, Value::Null);

        let value: Option<&str> = None;
        let value: Value = value.into();
        assert_eq!(value, Value::Null);

        let value: Option<f32> = None;
        let value: Value = value.into();
        assert_eq!(value, Value::Null);
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
        assert_eq!(Value::Utf8(&[97, 98, 99]).try_into(), Ok(vec![97, 98, 99]));

        assert_eq!(
            Value::Utf8(&[0, 0xFF, 0x80, 0xFF, 0xFF]).try_into(),
            Ok(vec![0, 0xFF, 0x80, 0xFF, 0xFF])
        );
    }
}
