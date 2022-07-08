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
    StreamFinished,  // stream of data returned None
    ContainerClosed, // stream of data returned 'ContainerEnd'
}

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct ChildStructure {
    some_unsigned: Option<u32>, // tag: 1
    some_signed: i16,           // tag: 2
}

impl<'a> ChildStructure {
    pub fn merge_decode(
        &mut self,
        source: &mut impl StreamingIterator<Item = Record<'a>>,
    ) -> Result<DecodeEnd, DecodeError> {
        loop {
            let record = source.next();

            let record = match record {
                None => return Ok(DecodeEnd::StreamFinished),
                Some(Record {
                    tag: _,
                    value: Value::ContainerEnd,
                }) => return Ok(DecodeEnd::ContainerClosed),
                Some(value) => value,
            };

            match record.tag {
                tlv_stream::TagValue::ContextSpecific { tag: 1 } => {
                    self.some_unsigned = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_signed = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                }
                _ => {
                    // TODO: log if skipping maybe
                }
            }
        }
    }

    pub fn decode(
        source: &mut impl StreamingIterator<Item = Record<'a>>,
    ) -> Result<Self, DecodeError> {
        let mut result = Self::default();
        if result.merge_decode(source)? != DecodeEnd::StreamFinished {
            // Unexpected container closed within the data
            return Err(DecodeError::InvalidNesting);
        }
        Ok(result)
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

impl<'a> TopStructure<'a> {
    pub fn merge_decode(
        &mut self,
        source: &mut impl StreamingIterator<Item = Record<'a>>,
    ) -> Result<DecodeEnd, DecodeError> {
        loop {
            let record = source.next();

            let record = match record {
                None => return Ok(DecodeEnd::StreamFinished),
                Some(Record {
                    tag: _,
                    value: Value::ContainerEnd,
                }) => return Ok(DecodeEnd::ContainerClosed),
                Some(value) => value,
            };

            match record.tag {
                tlv_stream::TagValue::ContextSpecific { tag: 1 } => {
                    self.some_nr = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_str = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 3 } => {
                    self.some_signed = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 4 } => {
                    if record.value != Value::ContainerStart(ContainerType::Structure) {
                        return Err(DecodeError::InvalidData);
                    }

                    self.child = Default::default();
                    let end = self.child.merge_decode(source)?;
                    if end != DecodeEnd::ContainerClosed {
                        return Err(DecodeError::InvalidData);
                    }
                }
                tlv_stream::TagValue::ContextSpecific { tag: 5 } => {
                    if record.value != Value::ContainerStart(ContainerType::Structure) {
                        return Err(DecodeError::InvalidData);
                    }

                    self.child2 = Some(Default::default());
                    if let Some(ref mut value) = self.child2 {
                        let end = value.merge_decode(source)?;
                        if end != DecodeEnd::ContainerClosed {
                            return Err(DecodeError::InvalidData);
                        }
                    } else {
                        return Err(DecodeError::Internal);
                    }
                }
                _ => {
                    // TODO: log if skipping maybe
                }
            }
        }
    }

    pub fn decode(
        source: &mut impl StreamingIterator<Item = Record<'a>>,
    ) -> Result<Self, DecodeError> {
        let mut result = Self::default();
        if result.merge_decode(source)? != DecodeEnd::StreamFinished {
            // Unexpected container closed within the data
            return Err(DecodeError::InvalidNesting);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use tlv_stream::{ContainerType, Record, TagValue, Value};

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
