use streaming_iterator::StreamingIterator;
use tlv_stream::{Record, Value};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DecodeError {
    InvalidData,    // failed to decode some data
    InvalidNesting, // mismatched start/end structures
}

#[derive(Debug, Copy, Clone, Default)]
pub struct TestStruct<'a> {
    some_nr: Option<u32>, // tag: 1
    some_str: &'a str,    // tag: 2
    some_signed: i16,     // tag: 3
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DecodeEnd {
    StreamFinished,  // stream of data returned None
    ContainerClosed, // stream of data returned 'ContainerEnd'
}

impl<'a> TestStruct<'a> {
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
                },
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_str = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                },
                tlv_stream::TagValue::ContextSpecific { tag: 3 } => {
                    self.some_signed = record
                        .value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidData)?
                },
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
    use tlv_stream::{Record, TagValue, Value};

    use crate::TestStruct;

    #[test]
    fn decode_test() {
        let s = TestStruct::default();

        assert_eq!(s.some_str, "");
        assert_eq!(s.some_nr, None);
        assert_eq!(s.some_signed, 0);
        

        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 1},
                value: Value::Unsigned(123),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2},
                value: Value::Utf8(&[65, 66, 67]),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 3},
                value: Value::Signed(-2),
            },
        ];
        let mut streamer = streaming_iterator::convert(records.iter().copied());
        
        let s = TestStruct::decode(&mut streamer).unwrap();
        
        assert_eq!(s.some_nr, Some(123));
        assert_eq!(s.some_str, "ABC");
        assert_eq!(s.some_signed, -2);
    }
}
