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
        
        Ok(String::from_utf8(value.try_into()?).map_err(|_| ConversionError::InvalidUtf8)?)
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
    }
}
