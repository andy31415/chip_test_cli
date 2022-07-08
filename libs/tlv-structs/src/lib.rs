use streaming_iterator::StreamingIterator;
use tlv_stream::{ContainerType, Record, Value};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DecodeError {
    InvalidData,    // failed to decode some data
    InvalidNesting, // mismatched start/end structures
    Internal,       // Internal logic error, should not happen
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DecodeEnd {
    StreamFinished, // stream of data returned None
    DataConsumed,   // read full value (single value or 'structure end')
}

pub trait TlvDecodable<'a, Source>
where
    Source: StreamingIterator<Item = Record<'a>>,
    Self: Sized + Default,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError>;

    fn decode(source: &mut Source) -> Result<Self, DecodeError> {
        let mut result = Self::default();
        if result.merge_decode(source)? != DecodeEnd::StreamFinished {
            // Unexpected container closed within the data
            return Err(DecodeError::InvalidNesting);
        }
        Ok(result)
    }
}

/// decodes a single value from a streaming iterator.
///
/// Assumes that the iterator has already been positioned to a valid location.
impl<'a, BaseType, Source, E> TlvDecodable<'a, Source> for BaseType
where
    Source: StreamingIterator<Item = Record<'a>>,
    BaseType: std::convert::TryFrom<tlv_stream::Value<'a>, Error = E> + Sized + Default,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        // The decoding is assumed to be already positioned to the right location
        match source.get() {
            None => Err(DecodeError::InvalidData),
            Some(record) => {
                *self = record
                    .value
                    .try_into()
                    .map_err(|_| DecodeError::InvalidData)?;
                Ok(DecodeEnd::DataConsumed)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct ChildStructure {
    some_unsigned: Option<u32>, // tag: 1
    some_signed: i16,           // tag: 2
}

impl<'a, Source> TlvDecodable<'a, Source> for ChildStructure
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        loop {
            let record = source.next();

            let record = match record {
                None => return Ok(DecodeEnd::StreamFinished),
                Some(Record {
                    tag: _,
                    value: Value::ContainerEnd,
                }) => return Ok(DecodeEnd::DataConsumed),
                Some(value) => value,
            };

            let decoded = match record.tag {
                tlv_stream::TagValue::ContextSpecific { tag: 1 } => {
                    self.some_unsigned.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_signed.merge_decode(source)?
                }
                _ => DecodeEnd::DataConsumed, // TODO: should we log skipped entry?
            };
            if decoded == DecodeEnd::StreamFinished {
                return Err(DecodeError::InvalidNesting);
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct TopStructure<'a> {
    some_nr: Option<u32>, // tag: 1
    some_str: &'a str,    // tag: 2
    some_signed: i16,     // tag: 3

    child: ChildStructure, // tag 4
    child2: Option<ChildStructure>, // tag 5

                           // TODO: array or list ?
}

impl<'a, Source> TlvDecodable<'a, Source> for TopStructure<'a>
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        loop {
            let record = source.next();

            let record = match record {
                None => return Ok(DecodeEnd::StreamFinished),
                Some(Record {
                    tag: _,
                    value: Value::ContainerEnd,
                }) => return Ok(DecodeEnd::DataConsumed),
                Some(value) => value,
            };

            let decoded = match record.tag {
                tlv_stream::TagValue::ContextSpecific { tag: 1 } => {
                    self.some_nr.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_str.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 3 } => {
                    self.some_signed.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 4 } => {
                    if record.value != Value::ContainerStart(ContainerType::Structure) {
                        return Err(DecodeError::InvalidData);
                    }

                    self.child = Default::default();
                    self.child.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 5 } => {
                    if record.value != Value::ContainerStart(ContainerType::Structure) {
                        return Err(DecodeError::InvalidData);
                    }

                    self.child2 = Some(Default::default());
                    //self.child2.merge_decode(source)?;
                    if let Some(ref mut value) = self.child2 {
                        value.merge_decode(source)?
                    } else {
                        return Err(DecodeError::Internal);
                    }
                }
                _ => DecodeEnd::DataConsumed, // TODO: log here?
            };
            if decoded != DecodeEnd::DataConsumed {
                return Err(DecodeError::InvalidNesting);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tlv_stream::{ContainerType, Record, TagValue, Value};

    use crate::TlvDecodable;
    use crate::TopStructure;

    #[test]
    fn decode_test() {
        let s = TopStructure::default();

        assert_eq!(s.some_str, "");
        assert_eq!(s.some_nr, None);
        assert_eq!(s.some_signed, 0);

        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(123),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Utf8(&[65, 66, 67]),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 3 },
                value: Value::Signed(-2),
            },
        ];
        let mut streamer = streaming_iterator::convert(records.iter().copied());

        let s = TopStructure::decode(&mut streamer).unwrap();

        assert_eq!(s.some_nr, Some(123));
        assert_eq!(s.some_str, "ABC");
        assert_eq!(s.some_signed, -2);
    }

    #[test]
    fn nested_decode() {
        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(123),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Utf8(&[65, 66, 67]),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 3 },
                value: Value::Signed(-2),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 4 },
                value: Value::ContainerStart(ContainerType::Structure),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(21),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Signed(-12),
            },
            Record {
                tag: TagValue::Anonymous,
                value: Value::ContainerEnd,
            },
        ];
        let mut streamer = streaming_iterator::convert(records.iter().copied());

        let mut s = TopStructure::decode(&mut streamer).unwrap();

        assert_eq!(s.some_nr, Some(123));
        assert_eq!(s.some_str, "ABC");
        assert_eq!(s.some_signed, -2);
        assert_eq!(s.child.some_signed, -12);
        assert_eq!(s.child.some_unsigned, Some(21));
        assert_eq!(s.child2, None);

        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 5 },
                value: Value::ContainerStart(ContainerType::Structure),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(22),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Signed(23),
            },
            Record {
                tag: TagValue::Anonymous,
                value: Value::ContainerEnd,
            },
        ];
        let mut streamer = streaming_iterator::convert(records.iter().copied());
        s.merge_decode(&mut streamer).unwrap();

        assert_eq!(s.child2.unwrap().some_signed, 23);
        assert_eq!(s.child2.unwrap().some_unsigned, Some(22));
    }
}
