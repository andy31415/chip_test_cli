use crate::Value;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ConversionError {
    InvalidType,
    ConversionFailed,
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

#[cfg(test)]
mod tests {
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
        
    }

}